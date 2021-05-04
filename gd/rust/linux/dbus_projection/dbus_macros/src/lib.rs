extern crate proc_macro;

use quote::{format_ident, quote, ToTokens};

use std::fs::File;
use std::io::Write;
use std::path::Path;

use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{Expr, FnArg, ImplItem, ItemImpl, ItemStruct, Meta, Pat, ReturnType, Type};

use crate::proc_macro::TokenStream;

fn debug_output_to_file(gen: &proc_macro2::TokenStream, filename: String) {
    let path = Path::new(filename.as_str());
    let mut file = File::create(&path).unwrap();
    file.write_all(gen.to_string().as_bytes()).unwrap();
}

/// Marks a method to be projected to a D-Bus method and specifies the D-Bus method name.
#[proc_macro_attribute]
pub fn dbus_method(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let ori_item: proc_macro2::TokenStream = item.clone().into();
    let gen = quote! {
        #[allow(unused_variables)]
        #ori_item
    };
    gen.into()
}

/// Generates a function to export a Rust object to D-Bus.
#[proc_macro_attribute]
pub fn generate_dbus_exporter(attr: TokenStream, item: TokenStream) -> TokenStream {
    let ori_item: proc_macro2::TokenStream = item.clone().into();

    let args = Punctuated::<Expr, Comma>::parse_separated_nonempty.parse(attr.clone()).unwrap();

    let fn_ident = if let Expr::Path(p) = &args[0] {
        p.path.get_ident().unwrap()
    } else {
        panic!("function name must be specified");
    };

    let dbus_iface_name = if let Expr::Lit(lit) = &args[1] {
        lit
    } else {
        panic!("D-Bus interface name must be specified");
    };

    let ast: ItemImpl = syn::parse(item.clone()).unwrap();
    let api_iface_ident = ast.trait_.unwrap().1.to_token_stream();

    let mut register_methods = quote! {};

    for item in ast.items {
        if let ImplItem::Method(method) = item {
            if method.attrs.len() != 1 {
                continue;
            }

            let attr = &method.attrs[0];
            if !attr.path.get_ident().unwrap().to_string().eq("dbus_method") {
                continue;
            }

            let attr_args = attr.parse_meta().unwrap();
            let dbus_method_name = if let Meta::List(meta_list) = attr_args {
                Some(meta_list.nested[0].clone())
            } else {
                None
            };

            if dbus_method_name.is_none() {
                continue;
            }

            let method_name = method.sig.ident;

            let mut arg_names = quote! {};
            let mut method_args = quote! {};
            let mut make_args = quote! {};
            let mut dbus_input_vars = quote! {};
            let mut dbus_input_types = quote! {};

            for input in method.sig.inputs {
                if let FnArg::Typed(ref typed) = input {
                    let arg_type = &typed.ty;
                    if let Pat::Ident(pat_ident) = &*typed.pat {
                        let ident = pat_ident.ident.clone();
                        let mut dbus_input_ident = ident.to_string();
                        dbus_input_ident.push_str("_");
                        let dbus_input_arg = format_ident!("{}", dbus_input_ident);
                        let ident_string = ident.to_string();

                        arg_names = quote! {
                            #arg_names #ident_string,
                        };

                        method_args = quote! {
                            #method_args #ident,
                        };

                        dbus_input_vars = quote! {
                            #dbus_input_vars #dbus_input_arg,
                        };

                        dbus_input_types = quote! {
                            #dbus_input_types
                            <#arg_type as DBusArg>::DBusType,
                        };

                        make_args = quote! {
                            #make_args
                            let #ident = <#arg_type as DBusArg>::from_dbus(
                                #dbus_input_arg,
                                conn_clone.clone(),
                                ctx.message().sender().unwrap().into_static(),
                                dc_watcher_clone.clone(),
                            );

                            if let Result::Err(e) = #ident {
                                return Err(dbus_crossroads::MethodErr::invalid_arg(
                                    e.to_string().as_str()
                                ));
                            }

                            let #ident = #ident.unwrap();
                        };
                    }
                }
            }

            let dbus_input_args = quote! {
                (#dbus_input_vars): (#dbus_input_types)
            };

            let mut output_names = quote! {};
            let mut output_type = quote! {};
            let mut ret = quote! {Ok(())};
            if let ReturnType::Type(_, t) = method.sig.output {
                output_type = quote! {#t,};
                ret = quote! {Ok((ret,))};
                output_names = quote! { "out", };
            }

            register_methods = quote! {
                #register_methods

                let conn_clone = conn.clone();
                let dc_watcher_clone = disconnect_watcher.clone();
                let handle_method = move |ctx: &mut dbus_crossroads::Context,
                                          obj: &mut ObjType,
                                          #dbus_input_args |
                      -> Result<(#output_type), dbus_crossroads::MethodErr> {
                    #make_args
                    let ret = obj.lock().unwrap().#method_name(#method_args);
                    #ret
                };
                ibuilder.method(
                    #dbus_method_name,
                    (#arg_names),
                    (#output_names),
                    handle_method,
                );
            };
        }
    }

    let gen = quote! {
        #ori_item

        type ObjType = std::sync::Arc<std::sync::Mutex<dyn #api_iface_ident + Send>>;

        pub fn #fn_ident(
            path: &'static str,
            conn: std::sync::Arc<SyncConnection>,
            cr: &mut dbus_crossroads::Crossroads,
            obj: ObjType,
            disconnect_watcher: Arc<Mutex<dbus_projection::DisconnectWatcher>>,
        ) {
            fn get_iface_token(
                conn: Arc<SyncConnection>,
                cr: &mut dbus_crossroads::Crossroads,
                disconnect_watcher: std::sync::Arc<std::sync::Mutex<dbus_projection::DisconnectWatcher>>,
            ) -> dbus_crossroads::IfaceToken<ObjType> {
                cr.register(#dbus_iface_name, |ibuilder| {
                    #register_methods
                })
            }

            let iface_token = get_iface_token(conn, cr, disconnect_watcher);
            cr.insert(path, &[iface_token], obj);
        }
    };

    // TODO: Have a switch to turn on/off this debug.
    debug_output_to_file(&gen, format!("/tmp/out-{}.rs", fn_ident.to_string()));

    gen.into()
}

fn copy_without_attributes(item: &TokenStream) -> TokenStream {
    let mut ast: ItemStruct = syn::parse(item.clone()).unwrap();
    for field in &mut ast.fields {
        field.attrs.clear();
    }

    let gen = quote! {
        #ast
    };

    gen.into()
}

/// Generates a DBusArg implementation to transform Rust plain structs to a D-Bus data structure.
// TODO: Support more data types of struct fields (currently only supports integers and enums).
#[proc_macro_attribute]
pub fn dbus_propmap(attr: TokenStream, item: TokenStream) -> TokenStream {
    let ori_item: proc_macro2::TokenStream = copy_without_attributes(&item).into();

    let ast: ItemStruct = syn::parse(item.clone()).unwrap();

    let args = Punctuated::<Expr, Comma>::parse_separated_nonempty.parse(attr.clone()).unwrap();
    let struct_ident =
        if let Expr::Path(p) = &args[0] { p.path.get_ident().unwrap().clone() } else { ast.ident };

    let struct_str = struct_ident.to_string();

    let mut make_fields = quote! {};
    let mut field_idents = quote! {};

    let mut insert_map_fields = quote! {};
    for field in ast.fields {
        let field_ident = field.ident;

        if field_ident.is_none() {
            continue;
        }

        let field_str = field_ident.as_ref().unwrap().clone().to_string();

        let propmap_attr = field.attrs.clone().into_iter().find(|x| {
            let ident = x.path.get_ident();

            if ident.is_none() {
                return false;
            }

            ident.unwrap().to_string().eq("dbus_propmap_field_propmap")
        });

        let field_type_str = if let Type::Path(t) = field.ty {
            t.path.get_ident().unwrap().to_string()
        } else {
            String::from("")
        };

        let field_type_ident = format_ident!("{}", field_type_str);

        field_idents = quote! {
            #field_idents #field_ident,
        };

        let make_field = if !propmap_attr.is_none() {
            quote! {
                let mut map: dbus::arg::PropMap = HashMap::new();

                let mut iter = #field_ident.as_iter().unwrap();
                let mut iter = iter.next().unwrap().as_iter().unwrap();

                let mut i1 = iter.next();
                let mut i2 = iter.next();
                while !i1.is_none() && !i2.is_none() {
                    let k = i1.unwrap().as_str().unwrap().to_string();
                    let v = dbus::arg::Variant(i2.unwrap().box_clone());
                    map.insert(k, v);
                    i1 = iter.next();
                    i2 = iter.next();
                }

                let #field_ident = #field_type_ident::from_dbus(
                    map,
                    conn.clone(),
                    remote.clone(),
                    disconnect_watcher.clone(),
                )?;
            }
        } else {
            quote! {
                match #field_ident.arg_type() {
                    dbus::arg::ArgType::Variant => {}
                    _ => {
                        return Err(Box::new(DBusArgError::new(String::from(format!(
                            "{}.{} must be a variant",
                            #struct_str, #field_str
                        )))));
                    }
                };
                let #field_ident = #field_ident.as_static_inner(0).unwrap();
                let any = #field_ident.as_any();
                if !any.is::<<#field_type_ident as DBusArg>::DBusType>() {
                    return Err(Box::new(DBusArgError::new(String::from(format!(
                        "{}.{} type does not match: expected {}, found {}",
                        #struct_str,
                        #field_str,
                        std::any::type_name::<<#field_type_ident as DBusArg>::DBusType>(),
                        #field_ident.arg_type().as_str(),
                    )))));
                }
                let #field_ident = *any.downcast_ref::<<#field_type_ident as DBusArg>::DBusType>().unwrap();
                let #field_ident = #field_type_ident::from_dbus(
                    #field_ident,
                    conn.clone(),
                    remote.clone(),
                    disconnect_watcher.clone(),
                )?;
            }
        };

        make_fields = quote! {
            #make_fields

            let #field_ident = match data.get(#field_str) {
                Some(data) => data,
                None => {
                    return Err(Box::new(DBusArgError::new(String::from(format!(
                        "{}.{} is required",
                        #struct_str, #field_str
                    )))));
                }
            };
            #make_field
        };

        insert_map_fields = quote! {
            #insert_map_fields
            let field_data = DBusArg::to_dbus(data.#field_ident)?;
            map.insert(String::from(#field_str), dbus::arg::Variant(Box::new(field_data)));
        };
    }

    let gen = quote! {
        #[allow(dead_code)]
        #ori_item

        impl DBusArg for #struct_ident {
            type DBusType = dbus::arg::PropMap;

            fn from_dbus(
                data: dbus::arg::PropMap,
                conn: Arc<SyncConnection>,
                remote: BusName<'static>,
                disconnect_watcher: Arc<Mutex<dbus_projection::DisconnectWatcher>>,
            ) -> Result<#struct_ident, Box<dyn Error>> {
                #make_fields

                return Ok(#struct_ident {
                    #field_idents
                    ..Default::default()
                });
            }

            fn to_dbus(data: #struct_ident) -> Result<dbus::arg::PropMap, Box<dyn Error>> {
                let mut map: dbus::arg::PropMap = HashMap::new();
                #insert_map_fields
                return Ok(map);
            }
        }
    };

    // TODO: Have a switch to turn this debug off/on.
    debug_output_to_file(&gen, format!("/tmp/out-{}.rs", struct_ident.to_string()));

    gen.into()
}

/// Generates a DBusArg implementation of a Remote RPC proxy object.
#[proc_macro_attribute]
pub fn dbus_proxy_obj(attr: TokenStream, item: TokenStream) -> TokenStream {
    let ori_item: proc_macro2::TokenStream = item.clone().into();

    let args = Punctuated::<Expr, Comma>::parse_separated_nonempty.parse(attr.clone()).unwrap();

    let struct_ident = if let Expr::Path(p) = &args[0] {
        p.path.get_ident().unwrap()
    } else {
        panic!("struct name must be specified");
    };

    let dbus_iface_name = if let Expr::Lit(lit) = &args[1] {
        lit
    } else {
        panic!("D-Bus interface name must be specified");
    };

    let mut method_impls = quote! {};

    let ast: ItemImpl = syn::parse(item.clone()).unwrap();
    let self_ty = ast.self_ty;
    let trait_ = ast.trait_.unwrap().1;

    for item in ast.items {
        if let ImplItem::Method(method) = item {
            if method.attrs.len() != 1 {
                continue;
            }

            let attr = &method.attrs[0];
            if !attr.path.get_ident().unwrap().to_string().eq("dbus_method") {
                continue;
            }

            let attr_args = attr.parse_meta().unwrap();
            let dbus_method_name = if let Meta::List(meta_list) = attr_args {
                Some(meta_list.nested[0].clone())
            } else {
                None
            };

            if dbus_method_name.is_none() {
                continue;
            }

            let method_sig = method.sig.clone();

            let mut method_args = quote! {};

            for input in method.sig.inputs {
                if let FnArg::Typed(ref typed) = input {
                    if let Pat::Ident(pat_ident) = &*typed.pat {
                        let ident = pat_ident.ident.clone();

                        method_args = quote! {
                            #method_args DBusArg::to_dbus(#ident).unwrap(),
                        };
                    }
                }
            }

            method_impls = quote! {
                #method_impls
                #[allow(unused_variables)]
                #method_sig {
                    let remote = self.remote.clone();
                    let objpath = self.objpath.clone();
                    let conn = self.conn.clone();
                    bt_topshim::topstack::get_runtime().spawn(async move {
                        let proxy = dbus::nonblock::Proxy::new(
                            remote,
                            objpath,
                            std::time::Duration::from_secs(2),
                            conn,
                        );
                        let future: dbus::nonblock::MethodReply<()> = proxy.method_call(
                            #dbus_iface_name,
                            #dbus_method_name,
                            (#method_args),
                        );
                        let _result = future.await;
                    });
                }
            };
        }
    }

    let gen = quote! {
        #ori_item

        impl RPCProxy for #self_ty {
            fn register_disconnect(&mut self, _disconnect_callback: Box<dyn Fn() + Send>) {}
        }

        struct #struct_ident {
            conn: Arc<SyncConnection>,
            remote: BusName<'static>,
            objpath: Path<'static>,
            disconnect_watcher: Arc<Mutex<DisconnectWatcher>>,
        }

        impl #trait_ for #struct_ident {
            #method_impls
        }

        impl RPCProxy for #struct_ident {
            fn register_disconnect(&mut self, disconnect_callback: Box<dyn Fn() + Send>) {
                self.disconnect_watcher.lock().unwrap().add(self.remote.clone(), disconnect_callback);
            }
        }

        impl DBusArg for Box<dyn #trait_ + Send> {
            type DBusType = Path<'static>;

            fn from_dbus(
                objpath: Path<'static>,
                conn: Arc<SyncConnection>,
                remote: BusName<'static>,
                disconnect_watcher: Arc<Mutex<DisconnectWatcher>>,
            ) -> Result<Box<dyn #trait_ + Send>, Box<dyn Error>> {
                Ok(Box::new(#struct_ident { conn, remote, objpath, disconnect_watcher }))
            }

            fn to_dbus(_data: Box<dyn #trait_ + Send>) -> Result<Path<'static>, Box<dyn Error>> {
                // This impl represents a remote DBus object, so `to_dbus` does not make sense.
                panic!("not implemented");
            }
        }
    };

    // TODO: Have a switch to turn this debug off/on.
    debug_output_to_file(&gen, format!("/tmp/out-{}.rs", struct_ident.to_string()));

    gen.into()
}

/// Generates the definition of `DBusArg` trait required for D-Bus projection.
///
/// Due to Rust orphan rule, `DBusArg` trait needs to be defined locally in the crate that wants to
/// use D-Bus projection. Providing `DBusArg` as a public trait won't let other crates implement
/// it for structs defined in foreign crates. As a workaround, this macro is provided to generate
/// `DBusArg` trait definition.
#[proc_macro]
pub fn generate_dbus_arg(_item: TokenStream) -> TokenStream {
    let gen = quote! {
        use dbus::arg::PropMap;
        use dbus::nonblock::SyncConnection;
        use dbus::strings::BusName;
        use dbus_projection::DisconnectWatcher;

        use std::error::Error;
        use std::fmt;
        use std::sync::{Arc, Mutex};

        #[derive(Debug)]
        pub(crate) struct DBusArgError {
            message: String,
        }

        impl DBusArgError {
            pub fn new(message: String) -> DBusArgError {
                DBusArgError { message }
            }
        }

        impl fmt::Display for DBusArgError {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}", self.message)
            }
        }

        impl Error for DBusArgError {}

        pub(crate) trait DBusArg {
            type DBusType;

            fn from_dbus(
                x: Self::DBusType,
                conn: Arc<SyncConnection>,
                remote: BusName<'static>,
                disconnect_watcher: Arc<Mutex<DisconnectWatcher>>,
            ) -> Result<Self, Box<dyn Error>>
            where
                Self: Sized;

            fn to_dbus(x: Self) -> Result<Self::DBusType, Box<dyn Error>>;
        }

        // Types that implement dbus::arg::Append do not need any conversion.
        pub(crate) trait DirectDBus {}
        impl DirectDBus for i32 {}
        impl DirectDBus for u32 {}
        impl DirectDBus for String {}
        impl<T: DirectDBus> DBusArg for T {
            type DBusType = T;

            fn from_dbus(
                data: T,
                _conn: Arc<SyncConnection>,
                _remote: BusName<'static>,
                _disconnect_watcher: Arc<Mutex<DisconnectWatcher>>,
            ) -> Result<T, Box<dyn Error>> {
                return Ok(data);
            }

            fn to_dbus(data: T) -> Result<T, Box<dyn Error>> {
                return Ok(data);
            }
        }

        impl<T: DBusArg> DBusArg for Vec<T> {
            type DBusType = Vec<T::DBusType>;

            fn from_dbus(
                data: Vec<T::DBusType>,
                conn: Arc<SyncConnection>,
                remote: BusName<'static>,
                disconnect_watcher: Arc<Mutex<DisconnectWatcher>>,
            ) -> Result<Vec<T>, Box<dyn Error>> {
                let mut list: Vec<T> = vec![];
                for prop in data {
                    let t = T::from_dbus(
                        prop,
                        conn.clone(),
                        remote.clone(),
                        disconnect_watcher.clone(),
                    )?;
                    list.push(t);
                }
                Ok(list)
            }

            fn to_dbus(data: Vec<T>) -> Result<Vec<T::DBusType>, Box<dyn Error>> {
                let mut list: Vec<T::DBusType> = vec![];
                for item in data {
                    let t = T::to_dbus(item)?;
                    list.push(t);
                }
                Ok(list)
            }
        }
    };

    // TODO: Have a switch to turn this debug off/on.
    debug_output_to_file(&gen, format!("/tmp/out-generate_dbus_arg.rs"));

    gen.into()
}
