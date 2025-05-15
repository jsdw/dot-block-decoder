use clap::Parser;
use subxt_core::{ config::PolkadotConfig, utils::AccountId32 };
use subxt_rpcs::{ RpcConfig, client::RpcClient, methods::ChainHeadRpcMethods, methods::chain_head::ArchiveCallResult };
use frame_metadata::{ RuntimeMetadataPrefixed, RuntimeMetadata };
use anyhow::Context;
use parity_scale_codec::Decode;
use frame_decode::extrinsics;
use scale_info_legacy::{ ChainTypeRegistry, TypeRegistrySet };

/// Historic type definitions for the Polkadot Relay chain for pre-V14 metadata.
/// If interacting with another chain, it's likely there will be some missing/different
/// types that need adding (eg Kusama was experimental and moved quickly prior to Polkadot,
/// leading to a bunch of runtime versions and type name changes prior to Polkadot, and some
/// pallets eg staking I think have slightly different types configured for Kusama & Polkadot).
static DEFAULT_POLKADOT_TYPES: &str = include_str!("../types/polkadot_types.yaml");

/// Default URL for the Polkadot RPC node, if one is not provided.
static DEFAULT_POLKADOT_RPC_URL: &str = "wss://rpc.polkadot.io";

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Opts {
    /// URL of the RPC node to connect to.
    #[arg(long, default_value = DEFAULT_POLKADOT_RPC_URL)]
    url: String,

    #[arg(long, default_value = DEFAULT_POLKADOT_TYPES)]
    types: String,

    /// Block number to obtain and decode
    #[arg(short, long)]
    block_number: usize
}


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opts = Opts::parse();

    // Create an RPC client.
    let rpc_client = RpcClient::from_url(&opts.url).await.with_context(move || {
        format!("Failed to connect to RPC node at {}", opts.url)
    })?;

    // Pick a set of RPC methods to use it with. We'll use the new ones, which
    // require that we're pointed at an archive node. We use the PolkadotConfig 
    // to configure the expected input/output types to align with those that Polkadot 
    // requires. Most chains use the same, but substrate being
    // so flexible means that this is not a guarantee.
    let rpc_methods = ChainHeadRpcMethods::<PolkadotConfig>::new(rpc_client);

    // Turn out block height into a block hash so that we can retrieve it.
    let block_hash = {
        // If the block height is greater than the last finalized block, there may 
        // be forks, and so the return type is a vec.
        let mut block_hashes = rpc_methods.archive_v1_hash_by_height(opts.block_number).await.with_context(|| {
            format!("Failed to get block hash for block number {}", opts.block_number)
        })?;
    
        // But we expect exactly one hash to be returned, as we're working 
        // with older blocks, so we'll complain if not.
        if block_hashes.len() != 1 {
            return Err(anyhow::anyhow!("Expected exactly one block hash at height {}, got {}", opts.block_number, block_hashes.len()));
        }
        block_hashes.remove(0)
    };

    // Fetch the block header and body. We unwrap here because we know that the hash
    // points to a valid block, so don't expect to get None back.
    let block_header = rpc_methods.archive_v1_header(block_hash).await.with_context(|| {
        format!("Failed to get the block header for block hash {block_hash}")
    })?.unwrap();
    let block_body = rpc_methods.archive_v1_body(block_hash).await.with_context(|| {
        format!("Failed to get the block body for block hash {block_hash}")
    })?.unwrap();

    // We can print details from the block header as-is, barring the digest bytes
    // which would need some decoding to make sense of:
    println!("block number: {}", block_header.number);
    println!("parent hash: {}", block_header.parent_hash);
    println!("state root: {}", block_header.state_root);
    println!("extrinsics root: {}", block_header.extrinsics_root);

    // To decode extrinsics, we need the metadata in order to know the shape of the extrinsics
    // at the current runtime, and the spec version to know which historic types to use, in the
    // event that we're decoding a historic block.
    let metadata = get_metadata(&rpc_methods, block_hash).await?;
    let spec_version = get_spec_version(&rpc_methods, block_hash).await?;
    let historic_type_info = load_historic_type_info(&opts.types, spec_version)?;

    // Now, for each extrinsic in the block, we'll decode it and print the output.
    for ext in block_body {
        let ext_bytes = ext.0;

        // Decode whatever we are interested out of the extrinsic:
        let ext_info = decode_extrinsic(&mut &*ext_bytes, &metadata, &historic_type_info)
            .with_context(|| "Failed to decode extrinsic")?;

        // And then print it out:
        match ext_info {
            Extrinsic::Unsigned { call_data } => {
                println!("{}.{}", call_data.pallet_name, call_data.call_name);
                println!("  Call data:");
                for (name, value) in call_data.args {
                    println!("    {name}: {value}");
                }
            }
            Extrinsic::Signed { address, signature, signed_exts, call_data } => {
                println!("{}.{}", call_data.pallet_name, call_data.call_name);
                println!("  Address: {address}");
                println!("  Signature: {signature}");
                println!("  Call data:");
                for (name, value) in call_data.args {
                    println!("    {name}: {value}");
                }
                println!("  Transaction extension data:");
                for (name, value) in signed_exts {
                    println!("    {name}: {value}");
                }
            }
            Extrinsic::General { signed_exts, call_data } => {
                println!("{}.{}", call_data.pallet_name, call_data.call_name);
                println!("  Call data:");
                for (name, value) in call_data.args {
                    println!("    {name}: {value}");
                }
                println!("  Transaction extension data:");
                for (name, value) in signed_exts {
                    println!("    {name}: {value}");
                }
            }
        }
    }

    Ok(()) 
}

// The information we get back about extrinsics changes a bit depending on the metadata version we're using to
// decode it. For old blocks, we get back a stringish Type ID signifying the pallet/name of each type. For
// newer (V14+) blocks, we get back a numeric type ID. Newer vs older blocks also require different type information;
// newer blocks can use the PortableRegistry in the metadata, whereas older blocks need provided information to map
// type names into type information. Due to this, our handling varies by metadata version. Nevertheless, we are able
// to be generic over how we decode things.
fn decode_extrinsic<'info>(bytes: &[u8], metadata: &'info RuntimeMetadataPrefixed, historic_types: &'info TypeRegistrySet<'static>) -> anyhow::Result<Extrinsic> {
    let ext = match &metadata.1 {
        RuntimeMetadata::V8(m) => decode_extrinsic_inner(bytes, m, historic_types),
        RuntimeMetadata::V9(m) => decode_extrinsic_inner(bytes, m, historic_types),
        RuntimeMetadata::V10(m) => decode_extrinsic_inner(bytes, m, historic_types),
        RuntimeMetadata::V11(m) => decode_extrinsic_inner(bytes, m, historic_types),
        RuntimeMetadata::V12(m) => decode_extrinsic_inner(bytes, m, historic_types),
        RuntimeMetadata::V13(m) => decode_extrinsic_inner(bytes, m, historic_types),
        RuntimeMetadata::V14(m) => decode_extrinsic_inner(bytes, m, &m.types),
        RuntimeMetadata::V15(m) => decode_extrinsic_inner(bytes, m, &m.types),
        RuntimeMetadata::V16(m) => decode_extrinsic_inner(bytes, m, &m.types),
        _ => anyhow::bail!("Only metadata V8 - V16 is supported"),
    }?;

    // Decode everything out of the extrinsic.
    fn decode_extrinsic_inner<Info, Resolver>(
        bytes: &[u8],
        args_info: &Info,
        type_resolver: &Resolver,
    ) -> anyhow::Result<Extrinsic>
    where
        Info: frame_decode::extrinsics::ExtrinsicTypeInfo,
        Info::TypeId: Clone + core::fmt::Display + core::fmt::Debug + Send + Sync + 'static,
        Resolver: scale_type_resolver::TypeResolver<TypeId = Info::TypeId>,
    {
        let cursor = &mut &*bytes;
        let extrinsic_info = extrinsics::decode_extrinsic(cursor, args_info, type_resolver)?;

        // Decode each call data argument into a Value<String>
        let call_data = {
            let args = extrinsic_info
                .call_data()
                .map(|arg| {
                    // We are given the range of bytes for each argument, and the type ID for
                    // each argument (which for older metadata is more like a string, and for
                    // newer metadata is a u32). Here, we use this information to decode into
                    // a scale_value::Value (turning the type ID into a string so that, whether
                    // we use old or new type information, it's the same output type).
                    //
                    // Anything that implements scale_decode::visitor::Visitor can be decoded
                    // into using this information. See https://docs.rs/scale-decode/latest/scale_decode/
                    // for more on this.
                    //
                    // scale_value::Value is nice though because it has a pretty string 
                    // representation This output can be customised via 
                    // https://docs.rs/scale-value/latest/scale_value/stringify/fn.to_writer_custom.html.
                    // It can also be serialized or deserialized or parsed from strings, and can represent
                    // any SCALE encodable type.
                    let decoded_arg = scale_value::scale::decode_as_type(
                        &mut &bytes[arg.range()],
                        arg.ty().clone(),
                        type_resolver,
                    )?
                    .map_context(|ctx| ctx.to_string());
                    Ok((arg.name().to_owned(), decoded_arg))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            ExtrinsicCallData {
                pallet_name: extrinsic_info.pallet_name().to_owned(),
                call_name: extrinsic_info.call_name().to_owned(),
                args,
            }
        };

        // If present, extract/decode the signature details.
        let signature = if let Some(signature_info) = extrinsic_info.signature_payload() {
            let address_bytes = &bytes[signature_info.address_range()];
            let address_string = address_bytes
                .try_into()
                // If the address looks SS58ish, we use out AccountId32 type to turn it
                // into an SS58 string (albeit with the generic prefix). Else, we just
                // print out the hex encoded bytes.
                .map(|b| AccountId32(b).to_string())
                .unwrap_or_else(|_e| format!("0x{}", hex::encode(address_bytes)));

            let signature_bytes = &bytes[signature_info.signature_range()];
            let signature_string = hex::encode(signature_bytes);

            Some((address_string, signature_string))
        } else {
            None
        };

        // If present, extrcat/decode the transaction extension details
        let extensions = if let Some(exts) = extrinsic_info.transaction_extension_payload() {
            let signed_exts = exts
                .iter()
                .map(|signed_ext| {
                    // As we did for call arguments, here we look over each transaciton extension
                    // and decode them into scale_value::Value's too.
                    let decoded_ext = scale_value::scale::decode_as_type(
                        &mut &bytes[signed_ext.range()],
                        signed_ext.ty().clone(),
                        type_resolver,
                    )?
                    .map_context(|ctx| ctx.to_string());
                    Ok((signed_ext.name().to_owned(), decoded_ext))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            Some(signed_exts)
        } else {
            None
        };

        // Return our extrinsic details
        match (signature, extensions) {
            (Some((address, signature)), Some(signed_exts)) => Ok(Extrinsic::Signed {
                address,
                signature,
                signed_exts,
                call_data,
            }),
            (None, Some(signed_exts)) => Ok(Extrinsic::General {
                signed_exts,
                call_data,
            }),
            _ => Ok(Extrinsic::Unsigned { call_data }),
        }
    }

    Ok(ext)
}

#[derive(Debug)]
pub enum Extrinsic {
    Unsigned {
        call_data: ExtrinsicCallData,
    },
    Signed {
        address: String,
        signature: String,
        signed_exts: Vec<(String, scale_value::Value<String>)>,
        call_data: ExtrinsicCallData,
    },
    General {
        signed_exts: Vec<(String, scale_value::Value<String>)>,
        call_data: ExtrinsicCallData,
    },
}

#[derive(Debug)]
pub struct ExtrinsicCallData {
    pub pallet_name: String,
    pub call_name: String,
    pub args: Vec<(String, scale_value::Value<String>)>,
}

fn load_historic_type_info(types_str: &str, spec_version: u32) -> anyhow::Result<TypeRegistrySet<'static>> {
    // Load the historic type info from the YAML file.
    let type_info: ChainTypeRegistry = serde_yaml::from_str(types_str)
        .with_context(|| "Failed to decode the historic type information")?;

    // Pull out the types we need for the actual runtimer spec version we're at.
    let type_info_for_spec_version = type_info
        .for_spec_version(spec_version as u64)
        .to_owned();

    Ok(type_info_for_spec_version)
}

async fn get_spec_version<T: RpcConfig>(rpc_methods: &ChainHeadRpcMethods<T>, block_hash: T::Hash) -> anyhow::Result<u32> {
    // make a runtime call to get the version information. This is also a constant
    // in the metadata and so we could fetch it from there to avoid the call, but it would be a 
    // bit more effort.
    let spec_version_bytes = {
        let call_res = rpc_methods.archive_v1_call(block_hash, "Core_version", &[])
            .await
            .with_context(|| "Failed to fetch the runtime version information")?;
        match call_res {
            ArchiveCallResult::Success(bytes) => bytes.0,
            ArchiveCallResult::Error(err) => anyhow::bail!("{err}")
        }
    };

    // We only care about the spec version, so just decode enough of this version information
    // to be able to pluck out what we want, and ignore the rest.
    let spec_version = {
        #[derive(parity_scale_codec::Decode)]
        struct SpecVersionHeader {
            _spec_name: String,
            _impl_name: String,
            _authoring_version: u32,
            spec_version: u32
        }
        SpecVersionHeader::decode(&mut &spec_version_bytes[..])
            .with_context(|| "Failed to decode the spec version")?
            .spec_version
    };

    Ok(spec_version)
}

async fn get_metadata<T: RpcConfig>(rpc_methods: &ChainHeadRpcMethods<T>, block_hash: T::Hash) -> anyhow::Result<RuntimeMetadataPrefixed> {
    // The block body contains extrinsics which we need to decode to make sense of them.
    // To decode extrinsics, we need the metadata for the runtime version at this block,
    // because it describes the available extrinsics and their arguments, so let's obtain that.
    let metadata_bytes = {
        let call_res = rpc_methods.archive_v1_call(block_hash, "Metadata_metadata", &[])
            .await
            .with_context(|| "Failed to fetch the metadata")?;
        match call_res {
            ArchiveCallResult::Success(bytes) => bytes.0,
            ArchiveCallResult::Error(err) => anyhow::bail!("{err}")
        }
    };

    // Decode these bytes from the (legacy, because we want to work with historic blocks) 
    // metadata runtime call into actual metadata.
    let metadata = {
        // Remove a length prefix.
        let cursor = &mut &metadata_bytes[..];
        let _len: parity_scale_codec::Compact<u64> = Decode::decode(cursor)
            .with_context(|| "Failed to decode the metadata length")?;

        // Now we can decode the remaining bytes.
        RuntimeMetadataPrefixed::decode(cursor)
            .with_context(|| "Failed to decode the metadata")?
    };

    Ok(metadata)
}