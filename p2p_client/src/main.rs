// main.rs
// by Ruben Boero, Lazuli Kleinhans
// April 21st, 2025
// CS347 Advanced Software Design

use std::net::{TcpStream, TcpListener};
use std::io::{self, Write, Read};
use std::thread::{self, sleep};
use std::time::Duration;
use std::env::args;
use std::process;


fn connect_sender_stream(send_ip: String, port: &String, username: &String) -> TcpStream {
    let send_addr: String = send_ip + ":" + &port;
    
    // loop until connection is successful
    loop {
        println!("Attempting to connect to {send_addr}...");
        match TcpStream::connect(&send_addr) {
            Ok(s) => {
                println!("Connected to {send_addr} as {username}");
                return s;
            },
            Err(e) => {
                eprintln!("Failed to connect to {send_addr}: {e}");
                sleep(Duration::from_secs(1));
            }
        };
    }
}


fn send_to_all_connections(streams: &Vec<TcpStream>, message: String) {
    for mut stream in streams {
        if let Err(e) = stream.write_all(message.as_bytes()) {
            eprintln!("Failed to write to stream: {e}");
            return;
        }
    }
}

fn start_sender_thread(send_addrs: Vec<String>, port: String, username: String) {
    thread::spawn(move || {
        
        // start a sender stream for every IP the user wants to talk to
        let mut senders: Vec<TcpStream> = vec![];
        for addr in send_addrs {
            senders.push(connect_sender_stream(addr.clone(), &port, &username));
        }

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
                send_to_all_connections(&senders, format!("[{username} disconnected]"));
                process::exit(0);
            }

            // send your message along with your username so others know who sent it
            message = format!("[{username}] {message}");

            send_to_all_connections(&senders, message);
        }
    });
}


fn run_client_server(send_addrs: &[String], port: String, username: String) {
    
    println!("Starting listener...");
    let listen_addr = String::from("0.0.0.0:") + &port;
    let listener = match TcpListener::bind(&listen_addr) {
        Ok(l) => {
            println!("Client listening on {}", &listen_addr);
            l
        }
        Err(e) => {
            eprintln!("Failed to bind: {}", e);
            return;
        }
    };
    println!("Successfully started listener.");



    println!("Starting sender thread...");
    let mut send_addrs_clone: Vec<String> = vec![];
    for addr in send_addrs {
        send_addrs_clone.push(addr.clone());
    }
    start_sender_thread(send_addrs_clone, port, username);
    println!("Successfully started sender thread.");


    // start handling incoming data and printing it to the terminal

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to accept connection: {e}");
                continue;
            }
        };
    
        // create new thread for each incoming stream to handle more than one connection
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

fn main() {
    // put all the command line arguments into a vector
    let args: Vec<String> = args().collect();
    
    if args.len() < 5 {
        eprintln!("Please specify a username, port number, and any number of IP addresses to connect to.\nUsage: cargo run p2p_client [username] [port number] [IP address ...]");
        process::exit(1);  // exit with error code 1 (common failure)
    }

    run_client_server(&args[4..], args[3].clone(), args[2].clone());
}