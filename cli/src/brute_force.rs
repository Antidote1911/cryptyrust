
#[cfg(test)]
mod tests {
    use rand::{thread_rng, RngCore};
    use std::io::Write;
    use itertools::Itertools;
    use std::time::Instant;

    struct ProgressUpdater {}

    impl cryptyrust_core::Ui for ProgressUpdater {
        fn output(&self, _percentage: i32) {}
    }

    #[test]
    fn brute_force_test() -> Result<(), Box<dyn std::error::Error>> {

        // generate random file, write to temp location
        let mut random_data = vec![0; (1<<10) * 100]; // 100KiB
        thread_rng().fill_bytes(&mut random_data);
        let mut temp_file = std::env::temp_dir();
        temp_file.push("rand.txt");
        let mut file = std::fs::File::create(&temp_file)?;
        file.write_all(&random_data)?;

        // encrypt file with 12-char password
        let pw = "abcdefghijkl".to_string();
        let in_file = temp_file.to_str().unwrap().to_string();
        let mut out_path = std::env::temp_dir();
        out_path.push("encrypted.txt");
        let out_file = out_path.to_str().unwrap().to_string();
        let config = cryptyrust_core::Config::new(&cryptyrust_core::Mode::Encrypt, pw, Some(in_file), Some(out_file.clone()), Box::new(ProgressUpdater{}));
        cryptyrust_core::main_routine(&config)?;

        // measure frequency of brute-force attempts
        /*
            Letters, numbers, and symbols makes 94 values. With a 12 character minimum, that makes 1,951,641,934,005,400 passwords.

        */

        let mut possible_chars = ('a'..='z').collect::<Vec<char>>();
        possible_chars.append(&mut ('A'..='Z').collect());
        possible_chars.append(&mut "0123456789!@#$%^&*()-_=+`~,./<>?;':\"[]{}\\|".chars().collect());
        let mut combiner = possible_chars.iter().combinations_with_replacement(10);
        println!("possible chars: {}", possible_chars.len());

        let num_combos = 1951641934005400.;
        let start_time = Instant::now();
        let mut attempts = 0;

        loop {
            let guess_chars = combiner
                .next() // get next combination from the iterator, which will be a Vec<&char>
                .ok_or("end of combinations")? // coerce None to Err so we can fit the surrounding function signature and use the question mark
                .iter() // have to iterate over it so we can...
                .cloned().cloned() // clone it twice, which is weird. we're dealing with references to references at this point I guess so have to undo it twice.
                .collect::<Vec<char>>(); // and then collect it into a vector of chars.
            let guess: String = guess_chars.into_iter().collect();
            let c = cryptyrust_core::Config::new(&cryptyrust_core::Mode::Decrypt, guess.clone(), Some(out_file.clone()), Some("./result".to_string()), Box::new(ProgressUpdater{}));
            assert!(cryptyrust_core::main_routine(&c).is_err());

            attempts += 1;
            let elapsed = Instant::now().duration_since(start_time.clone()).as_secs_f64();
            if elapsed == 0. {continue};
            let attempts_per_sec = attempts as f64 / elapsed;
            // attempts_per_sec * num_secs = num_combos, so num_secs = num_combos / attempts_per_sec
            let num_secs = num_combos / attempts_per_sec;
            let num_years = num_secs / (60. * 60. * 24. * 365.);
            if attempts % 100 == 0 {
                println!("guess: {}", guess);
                println!("at {:.3} attempts per second, it would take {:.2} years to test all 12-character passwords including lower-/uppercase letters, numbers, and symbols.", attempts_per_sec, num_years);
            }
        }
        Ok(())
    }
}
