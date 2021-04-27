extern crate proc_macro;

use quote::quote;

use std::fs::File;
use std::io::Write;
use std::path::Path;

use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{Expr, FnArg, ItemTrait, Meta, Pat, TraitItem};

use crate::proc_macro::TokenStream;

fn debug_output_to_file(gen: &proc_macro2::TokenStream, filename: String) {
    let path = Path::new(filename.as_str());
    let mut file = File::create(&path).unwrap();
    file.write_all(gen.to_string().as_bytes()).unwrap();
}

/// Specifies the `Stack::Message` associated with a topshim callback.
#[proc_macro_attribute]
pub fn stack_message(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let ori_item: proc_macro2::TokenStream = item.clone().into();
    let gen = quote! {
        #[allow(unused_variables)]
        #ori_item
    };
    gen.into()
}

/// Generates a topshim callback object that contains closures.
///
/// The closures are generated to be calls to the corresponding `Stack::Message`.
#[proc_macro_attribute]
pub fn btif_callbacks_generator(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = Punctuated::<Expr, Comma>::parse_separated_nonempty.parse(attr.clone()).unwrap();

    let fn_ident = if let Expr::Path(p) = &args[0] {
        p.path.get_ident().unwrap()
    } else {
        panic!("function name must be specified");
    };

    let callbacks_struct_ident = if let Expr::Path(p) = &args[1] {
        p.path.get_ident().unwrap()
    } else {
        panic!("callbacks struct ident must be specified");
    };

    let ast: ItemTrait = syn::parse(item.clone()).unwrap();

    let mut fn_names = quote! {};
    let mut closure_defs = quote! {};
    for attr in ast.items {
        if let TraitItem::Method(m) = attr {
            if m.attrs.len() != 1 {
                continue;
            }

            let attr = &m.attrs[0];
            if !attr.path.get_ident().unwrap().to_string().eq("stack_message") {
                continue;
            }

            let attr_args = attr.parse_meta().unwrap();
            let stack_message = if let Meta::List(meta_list) = attr_args {
                Some(meta_list.nested[0].clone())
            } else {
                None
            };

            if stack_message.is_none() {
                continue;
            }

            let mut arg_names = quote! {};
            for input in m.sig.inputs {
                if let FnArg::Typed(t) = input {
                    if let Pat::Ident(i) = *t.pat {
                        let attr_name = i.ident;
                        arg_names = quote! { #arg_names #attr_name, };
                    }
                }
            }
            let method_ident = m.sig.ident;

            fn_names = quote! {
                #fn_names
                #method_ident,
            };

            closure_defs = quote! {
                #closure_defs
                let tx_clone = tx.clone();
                let #method_ident = Box::new(move |#arg_names| {
                    let tx = tx_clone.clone();
                    topstack::get_runtime().spawn(async move {
                        let result = tx.send(Message::#stack_message(#arg_names)).await;
                        if let Err(e) = result {
                            eprintln!("Error in sending message: {}", e);
                        }
                    });
                });
            };
        }
    }

    let ori_item = proc_macro2::TokenStream::from(item.clone());

    let gen = quote! {
        #ori_item

        /// Returns a callback object to be passed to topshim.
        pub fn #fn_ident(tx: tokio::sync::mpsc::Sender<Message>) -> #callbacks_struct_ident {
            #closure_defs
            #callbacks_struct_ident {
                #fn_names
                // TODO: Handle these in main loop.
                acl_state_changed: Box::new(|_, _, _, _| {}),
                bond_state_changed: Box::new(|_, _, _| {}),
                device_found: Box::new(|_, _| {}),
                discovery_state_changed: Box::new(|_| {}),
                pin_request: Box::new(|_, _, _, _| {}),
                remote_device_properties_changed: Box::new(|_, _, _, _| {}),
                ssp_request: Box::new(|_, _, _, _, _| {}),
            }
        }
    };

    // TODO: Have a simple framework to turn on/off macro-generated code debug.
    debug_output_to_file(&gen, format!("/tmp/out-{}.rs", fn_ident.to_string()));

    gen.into()
}
