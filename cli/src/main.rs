use clap::Parser;
use dane::dns_name::DaneDnsName;
use dane::fetch::DaneFetch;
use miette::Report;
use miette::Result;
use openpgp_tester_lib::load::load_keys;

#[derive(Parser, Debug)]
#[command(version, author, about, long_about = None)]
struct Args {
    /// The GPG User ID to look up (example: Joe.Doe@example.org)
    #[arg(short, long, required = true)]
    user_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let user_id = args.user_id;

    let dane_dns_name = DaneDnsName::new(&user_id)?;

    println!("DANE DNS name: {}", dane_dns_name.fqdn);

    let dns_server = std::env::var("DNS_SERVER").ok();
    let dane_fetch = DaneFetch::fetch(&dane_dns_name, dns_server.as_deref()).await;

    if dane_fetch.data.is_empty() {
        println!("DANE lookup failed with following errors:");
        for error in dane_fetch.errors {
            println!("{:?}", Report::new(error));
        }
        return Ok(());
    }

    if !dane_fetch.errors.is_empty() {
        println!("DANE lookup was successful with warnings:");
        for error in dane_fetch.errors {
            println!("{:?}", Report::new(error));
        }
    }

    println!("Tests:");
    for success in dane_fetch.successes {
        println!(" - {success:?} Passed")
    }

    for (index, data) in dane_fetch.data.into_iter().enumerate() {
        let record = index + 1;
        match load_keys(data.into()) {
            Ok(keys) => {
                if keys.len() > 1 {
                    println!(
                        "Record {record} contains {} keys; RFC 7929 section 2 requires exactly one key per record",
                        keys.len()
                    );
                }
                for key in keys {
                    println!("Record {record} key:");
                    println!("Key fingerprint: {}", key.fingerprint);
                    println!("Revocation status: {}", key.revocation_status);
                    println!("Expiry status: {}", key.expiry);
                    println!("Algorithm: {}", key.algorithm);
                    println!("Randomart:\n{}", key.randomart);
                }
            }
            Err(error) => {
                println!("Record {record} key loading failed with following errors:");
                println!("{:?}", Report::new(error));
            }
        };
    }

    Ok(())
}
