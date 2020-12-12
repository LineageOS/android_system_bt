//! Core dependency injection macros

extern crate proc_macro;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream, Result};
use syn::punctuated::Punctuated;
use syn::{braced, parse, parse_macro_input, FnArg, Ident, ItemFn, Token, Type, DeriveInput, Path};

/// Defines a provider function, with generated helper that implicitly fetches argument instances from the registry
#[proc_macro_attribute]
pub fn provides(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let function: ItemFn = parse(item).expect("can only be applied to functions");

    // Create the info needed to refer to the function & the injected version we generate
    let ident = function.sig.ident.clone();
    let injected_ident = format_ident!("__gddi_{}_injected", ident);

    // Create the info needed to generate the call to the original function
    let inputs = function.sig.inputs.iter().map(|arg| {
        if let FnArg::Typed(t) = arg {
            return t.ty.clone();
        }
        panic!("can't be applied to struct methods");
    });
    let local_var_idents = (0..inputs.len()).map(|i| format_ident!("__input{}", i));
    let local_var_idents_for_call = local_var_idents.clone();

    let emitted_code = quote! {
        // Injecting wrapper
        fn #injected_ident(registry: std::sync::Arc<gddi::Registry>) -> std::pin::Pin<gddi::ProviderFutureBox> {
            Box::pin(async move {
                // Create a local variable for each argument, to ensure they get generated in a
                // deterministic order (compiler complains otherwise)
                #(let #local_var_idents = registry.get::<#inputs>().await;)*

                // Actually call the original function
                Box::new(#ident(#(#local_var_idents_for_call),*).await) as Box<dyn std::any::Any>
            })
        }
        #function
    };
    emitted_code.into()
}

struct ModuleDef {
    name: Ident,
    providers: Punctuated<ProviderDef, Token![,]>,
    submodules: Punctuated<Path, Token![,]>,
}

enum ModuleEntry {
    Providers(Punctuated<ProviderDef, Token![,]>),
    Submodules(Punctuated<Path, Token![,]>),
}

struct ProviderDef {
    ty: Type,
    ident: Ident,
}

impl Parse for ModuleDef {
    fn parse(input: ParseStream) -> Result<Self> {
        // first thing is the module name followed by a comma
        let name = input.parse()?;
        input.parse::<Token![,]>()?;
        // Then comes submodules or provider sections, in any order
        let entries: Punctuated<ModuleEntry, Token![,]> = Punctuated::parse_terminated(input)?;
        let mut providers = Punctuated::new();
        let mut submodules = Punctuated::new();
        for entry in entries.into_iter() {
            match entry {
                ModuleEntry::Providers(value) => {
                    if !providers.is_empty() {
                        panic!("providers specified more than once");
                    }
                    providers = value;
                },
                ModuleEntry::Submodules(value) => {
                    if !submodules.is_empty() {
                        panic!("submodules specified more than once");
                    }
                    submodules = value;
                },
            }
        }
        Ok(ModuleDef {
            name,
            providers,
            submodules,
        })
    }
}

impl Parse for ProviderDef {
    fn parse(input: ParseStream) -> Result<Self> {
        // A provider definition follows this format: <Type> -> <function name>
        let ty = input.parse()?;
        input.parse::<Token![=>]>()?;
        let ident = input.parse()?;
        Ok(ProviderDef { ty, ident })
    }
}

impl Parse for ModuleEntry {
    fn parse(input: ParseStream) -> Result<Self> {
        match input.parse::<Ident>()?.to_string().as_str() {
            "providers" => {
                let entries;
                braced!(entries in input);
                Ok(ModuleEntry::Providers(
                    entries.parse_terminated(ProviderDef::parse)?,
                ))
            }
            "submodules" => {
                let entries;
                braced!(entries in input);
                Ok(ModuleEntry::Submodules(
                    entries.parse_terminated(Path::parse)?,
                ))
            }
            keyword => {
                panic!("unexpected keyword: {}", keyword);
            }
        }
    }
}

/// Emits a module function that registers submodules & providers with the registry
#[proc_macro]
pub fn module(item: TokenStream) -> TokenStream {
    let module = parse_macro_input!(item as ModuleDef);
    let init_ident = module.name.clone();
    let types = module.providers.iter().map(|p| p.ty.clone());
    let provider_idents = module
        .providers
        .iter()
        .map(|p| format_ident!("__gddi_{}_injected", p.ident.clone()));
    let submodule_idents = module.submodules.iter();
    let emitted_code = quote! {
        #[doc(hidden)]
        #[allow(missing_docs)]
        pub fn #init_ident(builder: gddi::RegistryBuilder) -> gddi::RegistryBuilder {
            // Register all providers on this module
            builder#(.register_provider::<#types>(Box::new(#provider_idents)))*
            // Register all submodules on this module
            #(.register_module(#submodule_idents))*
        }
    };
    emitted_code.into()
}

/// Emits a default implementation for Stoppable that does nothing;
#[proc_macro_derive(Stoppable)]
pub fn derive_nop_stop(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let ident = input.ident;
    let emitted_code = quote! {
        impl gddi::Stoppable for #ident {}
    };
    emitted_code.into()
}
