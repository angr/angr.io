// fauxware, in Rust — the classic angr demo binary, ported line for line from
// fauxware.c. Same backdoor, same prompts, same "Go away!".
use std::fs::File;
use std::io::Read;

const SNEAKY: &[u8; 8] = b"SOSNEAKY";

fn authenticate(username: &[u8; 8], password: &[u8; 8]) -> bool {
    // evil back d00r
    if password == SNEAKY {
        return true;
    }

    let mut stored = [0u8; 8];
    let name = String::from_utf8_lossy(username);
    if let Ok(mut pwfile) = File::open(name.trim_end_matches('\0')) {
        let _ = pwfile.read(&mut stored);
    }

    password == &stored
}

fn accepted() {
    println!("Welcome to the admin console, trusted user!");
}

fn rejected() -> ! {
    print!("Go away!");
    std::process::exit(1);
}

fn main() {
    let mut stdin = std::io::stdin();
    let mut username = [0u8; 8];
    let mut password = [0u8; 8];
    let mut newline = [0u8; 1];

    println!("Username: ");
    let _ = stdin.read(&mut username);
    let _ = stdin.read(&mut newline);
    println!("Password: ");
    let _ = stdin.read(&mut password);
    let _ = stdin.read(&mut newline);

    if authenticate(&username, &password) {
        accepted();
    } else {
        rejected();
    }
}
