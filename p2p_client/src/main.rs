// main.rs
// by Ruben Boero, Lazuli Kleinhans
// April 17th, 2025
// CS347 Advanced Software Design

use std::net::TcpStream;
use std::net::TcpListener;
use std::io::Read;
use std::io::{self, Write};
use std::thread;
use std::env::args;
use std::process;
use std::thread::sleep;
use std::time::Duration;

pub fn run_client_server(send_addrs: &[String], port: &String, username: &String) {

    // start a sender thread for every IP the user wants to talk to
    for addr in send_addrs {
        spawn_sender_thread(addr.clone(), port.clone(), username.clone());
    }

    // handle incoming data and print it to the terminal
    println!("Starting listener...");

    let listen_addr = String::from("0.0.0.0:") + port;

    let listener = match TcpListener::bind(&listen_addr) {
        Ok(l) => {
            println!("Server listening on {}", &listen_addr);
            l
        }
        Err(e) => {
            eprintln!("Failed to bind: {}", e);
            return;
        }
    };

    println!("Successfully started listener.");
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to accept connection: {e}");
                continue;
            }
        };
    
        // create new thread for each incoming stream to handle more than a 2 agent connection
        thread::spawn(move || {
            let mut buffer: [u8; 512] = [0; 512];
    
            loop {
                let num_bytes_read = match stream.read(&mut buffer) {
                    Ok(0) => {
                        println!("Partner disconnected");
                        break;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("Failed to read from stream: {e}");
                        break;
                    }
                };
    
                let received = String::from_utf8_lossy(&buffer[..num_bytes_read]);
                println!("{}", received.trim());
            }
        });
    }
}

fn spawn_sender_thread(send_ip: String, port: String, username: String) {
    thread::spawn(move || {
        let mut stream: TcpStream;
        let send_addr: String = send_ip + ":" + &port;
        
        // loop until connection is successful
        loop {
            println!("Attempting to connect to {send_addr}...");
            match TcpStream::connect(&send_addr) {
                Ok(s) => {
                    println!("Connected to {send_addr} as {username}");
                    stream = s;
                    break;
                },
                Err(e) => {
                    eprintln!("Failed to connect to {send_addr}: {e}");
                    sleep(Duration::from_secs(1));
                }
            };
        }

        println!("Successfully started sender thread.");
        
        loop {
            let mut message = String::new();

            // if let tries to match the output of read_line to Err, if it does match, it prints error message,
            // but if there is no error (Ok returned from read_line), then nothing happens
            if let Err(e) = io::stdin().read_line(&mut message) {
                eprintln!("Failed to read line: {e}");
                return;
            }

            if message.trim() == String::from("/exit"){
                println!("Goodbye!");
                // tell other users you disconnected
                match stream.write_all(format!("[{username} disconnected]").as_bytes()) {
                    Ok(_) => (),
                    Err(e) => {
                        eprintln!("Failed to send disconnect message: {e}");
                    }
                }
                process::exit(0);
            }

            // send your message along with your username so others know who sent it
            message = format!("[{username}] {message}");

            match stream.write_all(message.as_bytes()) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!("Failed to write to stream: {e}");
                    return;
                }
            }
        }
    });
}

fn main() {
    // put all the command line arguments into a vector
    let args: Vec<String> = args().collect();
    
    if args.len() < 5 {
        eprintln!("Please specify a username, port number, and any number of IP addresses to connect to.\nUsage: cargo run p2p_client [username] [port number] [IP address ...]");
        process::exit(1);  // exit with error code 1 (common failure)
    }

    run_client_server(&args[4..], &args[3], &args[2]);
}