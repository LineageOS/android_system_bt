//! Macros simplifying grpc service definitions

extern crate proc_macro;
use proc_macro::{TokenStream, TokenTree};
use quote::{format_ident, quote, quote_spanned};
use syn::parse::{Parse, ParseStream, Result};
use syn::{
    braced, parenthesized, parse_macro_input, parse_quote, Block, Expr, FnArg, Ident,
    ImplItemMethod, PatType, Path, Receiver, Token, Type,
};

/// provices shortcut syntax for defining proto-based rpc services
#[proc_macro]
pub fn grpc_service(item: TokenStream) -> TokenStream {
    let service = parse_macro_input!(item as ServiceDef);
    let grpc_trait = service.grpc_trait.clone();
    let struct_ = service.struct_.clone();
    let struct_for_facade = service.struct_.clone();
    let functions = service.items.iter().map(|i| match i {
        ServiceItem::Raw(inner) => Some(inner.clone()),
        ServiceItem::Rpc(inner) => Some(inner.clone().generate_fn()),
    });

    let mut grpc_path = grpc_trait.clone().segments;
    let grpc_create_fn = format_ident!(
        "create_{}",
        to_snake_case(&grpc_path.pop().unwrap().into_value().ident.to_string().as_str())
    );

    let emitted_code = quote! {
        impl #grpc_trait for #struct_ {
            #(#functions)*
        }

        impl bt_common::GrpcFacade for #struct_for_facade {
            fn into_grpc(self) -> grpcio::Service {
                #grpc_path#grpc_create_fn(self)
            }
        }
    };

    emitted_code.into()
}

struct ServiceDef {
    grpc_trait: Path,
    struct_: Type,
    items: Vec<ServiceItem>,
}

enum ServiceItem {
    Raw(ImplItemMethod),
    Rpc(RpcItem),
}

#[derive(Clone)]
struct RpcItem {
    name: Ident,
    input: PatType,
    output: RpcReturnType,
    unimplemented: bool,
    drain: Option<Box<Expr>>,
    code: Option<Block>,
}

impl RpcItem {
    fn generate_fn(self) -> ImplItemMethod {
        let name = self.name;
        let input = self.input;
        let output = self.output.type_;
        let tokens = match (self.drain, self.code) {
            (Some(drain), None) if self.output.stream => {
                quote_spanned! {
                    name.span()=>
                    fn #name(&mut self, _ctx: grpcio::RpcContext<'_>, #input, mut sink: grpcio::ServerStreamingSink<#output>) {
                        let stream = #drain.clone();
                        self.rt.spawn(async move {
                            while let Some(item) = stream.lock().await.recv().await {
                                sink.send((item.to_proto(), grpcio::WriteFlags::default())).await.unwrap();
                            }
                        });
                    }
                }
            }
            (Some(drain), None) if !self.output.stream => {
                let input_pat = input.clone().pat;
                quote_spanned! {
                    name.span()=>
                    fn #name(&mut self, _ctx: grpcio::RpcContext<'_>, #input, sink: grpcio::UnarySink<#output>) {
                        let channel = #drain.clone();
                        self.rt.block_on(async move {
                            channel.send(#input_pat.to_packet()).await.unwrap();
                        });
                        sink.success(Empty::default());
                    }
                }
            }
            (None, Some(code)) if !self.output.stream => {
                let tokens = quote! { #code };
                let rewritten_code = syn::parse::<Block>(replace_self(tokens.into())).unwrap();
                quote_spanned! {
                    name.span()=>
                    fn #name(&mut self, _ctx: grpcio::RpcContext<'_>, #input, sink: grpcio::UnarySink<#output>) {
                        let mut ___implicit_self___ = self.clone();
                        self.rt.block_on(async move {
                            #rewritten_code
                        });
                        sink.success(Empty::default());
                    }
                }
            }
            (None, None) if self.unimplemented => {
                let sink_type = format_ident!(
                    "{}",
                    if self.output.stream { "ServerStreamingSink" } else { "UnarySink" }
                );
                quote_spanned! {
                    name.span()=>
                    fn #name(&mut self, _ctx: grpcio::RpcContext<'_>, #input, _sink: grpcio::#sink_type<#output>) {
                        unimplemented!();
                    }
                }
            }
            (_, _) => {
                let sink_type = format_ident!(
                    "{}",
                    if self.output.stream { "ServerStreamingSink" } else { "UnarySink" }
                );
                quote_spanned! {
                    name.span()=>
                    fn #name(&mut self, _ctx: grpcio::RpcContext<'_>, #input, _sink: grpcio::#sink_type<#output>) {
                        compile_error!("support for this syntax is not supported yet");
                    }
                }
            }
        };

        syn::parse(tokens.into()).unwrap()
    }
}

#[derive(Clone)]
struct RpcReturnType {
    type_: Type,
    stream: bool,
}

impl Parse for ServiceDef {
    fn parse(input: ParseStream) -> Result<Self> {
        let _impl_token: Token![impl] = input.parse()?;
        let grpc_trait = input.parse()?;
        let _for: Token![for] = input.parse()?;
        let struct_ = input.parse()?;
        let content;
        braced!(content in input);

        let mut items = Vec::new();
        while !content.is_empty() {
            items.push(content.parse()?);
        }

        Ok(ServiceDef { grpc_trait, struct_, items })
    }
}

impl Parse for ServiceItem {
    fn parse(input: ParseStream) -> Result<Self> {
        if input.peek(Token![fn]) {
            Ok(ServiceItem::Raw(input.parse()?))
        } else {
            match input.parse::<Ident>()?.to_string().as_str() {
                "rpc" => Ok(ServiceItem::Rpc(input.parse()?)),
                keyword => panic!("unexpected keyword {}", keyword),
            }
        }
    }
}

impl Parse for RpcItem {
    fn parse(input: ParseStream) -> Result<Self> {
        let name: Ident = input.parse()?;
        let rpc_input;
        parenthesized!(rpc_input in input);
        let receiver: Receiver = rpc_input.parse()?;
        if receiver.mutability.is_none() {
            panic!("self should be mutable");
        }
        if receiver.reference.is_none() {
            panic!("self should be by reference");
        }
        let rpc_input: FnArg = if rpc_input.is_empty() {
            parse_quote! {
                _arg: Empty
            }
        } else {
            rpc_input.parse::<Token![,]>()?;
            rpc_input.parse()?
        };
        let rpc_input = match rpc_input {
            FnArg::Receiver(r) => panic!("did not expect {:?}", r),
            FnArg::Typed(t) => t,
        };

        let output = if input.peek(Token![->]) {
            let _arrow: Token![->] = input.parse()?;
            let stream = input.peek2(Ident);
            if stream && input.parse::<Ident>()?.to_string().as_str() != "stream" {
                panic!("expected \'stream\' keyword");
            }
            RpcReturnType { type_: input.parse()?, stream }
        } else {
            RpcReturnType {
                type_: parse_quote! {
                    Empty
                },
                stream: false,
            }
        };
        let (unimplemented, drain, code) = if input.peek(Token![=>]) {
            input.parse::<Token![=>]>()?;
            match input.parse::<Ident>()?.to_string().as_str() {
                "unimplemented" => {
                    input.parse::<Token![!]>()?;
                    let contents;
                    parenthesized!(contents in input);
                    if !contents.is_empty() {
                        panic!("expected empty unimplemented!()");
                    }
                    (true, None, None)
                }
                "drains" if output.stream => (false, Some(input.parse()?), None),
                "into" if !output.stream => (false, Some(input.parse()?), None),
                keyword => panic!("unexpected keyword {}", keyword),
            }
        } else {
            (false, None, Some(input.parse()?))
        };

        Ok(RpcItem { name, input: rpc_input, output, unimplemented, drain, code })
    }
}

fn to_snake_case(s: &str) -> String {
    let mut output = String::default();
    let mut first = true;
    for c in s.chars() {
        if c.is_uppercase() && !first {
            output.push('_');
        }
        output.push_str(&c.to_lowercase().to_string());
        first = false;
    }

    output
}

fn replace_self(stream: TokenStream) -> TokenStream {
    stream
        .into_iter()
        .map(|tt| match tt {
            TokenTree::Ident(i) if i.to_string() == "self" => {
                TokenTree::Ident(proc_macro::Ident::new("___implicit_self___", i.span()))
            }
            TokenTree::Group(g) => {
                let mut group = proc_macro::Group::new(g.delimiter(), replace_self(g.stream()));
                group.set_span(g.span());
                TokenTree::Group(group)
            }
            other => other,
        })
        .collect()
}
