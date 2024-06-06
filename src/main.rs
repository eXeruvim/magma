use rand::Rng; 
use std::convert::TryInto; 
use std::env; 
use std::error::Error; 
use std::fs::{self, File}; 
use std::io::{Read, Write};
use std::path::Path; 

/*

https://tc26.ru/standard/gost/GOST_R_3412-2015.pdf

*/

// Определяем таблицу подстановки, используемую в раунде Фейстеля
const SUB_TAB: [[u8; 16]; 8] = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 14, 6, 7, 0, 10, 5, 3, 9, 15, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
];

// Функция для генерации случайного ключа
fn generate_random_key() -> String {
    // Создаем генератор случайных чисел
    let mut rng = rand::thread_rng();
    // Генерируем случайные байты и преобразуем их в шестнадцатеричную строку
    (0..32).map(|_| format!("{:02x}", rng.gen::<u8>())).collect()
}

// Функция раунда Фейстеля
fn feistel_round(left: u32, right: u32, key: u32) -> (u32, u32) {
    // Добавляем правую половину к ключу и преобразуем в байты
    let mut temp = (right.wrapping_add(key)).to_be_bytes();
    // Применяем таблицу подстановки к каждому байту
    for i in 0..4 {
        let upper = (temp[i] >> 4) as usize;
        let lower = (temp[i] & 0x0F) as usize;
        temp[i] = (SUB_TAB[i][upper] << 4) | SUB_TAB[i][lower];
    }
    // Поворачиваем результат влево на 11 бит и возвращаем обновленные половины
    let temp = u32::from_be_bytes(temp).rotate_left(11);
    (right, left ^ temp)
}

// Функция шифрования блока данных
fn encrypt_block(block: [u8; 8], round_keys: &[u32; 8]) -> [u8; 8] {
    // Преобразуем первые 4 байта блока в 32-битное число для левой половины
    let mut left = u32::from_be_bytes(block[0..4].try_into().expect("Неправильный размер среза"));
    // Преобразуем последние 4 байта блока в 32-битное число для правой половины
    let mut right = u32::from_be_bytes(block[4..8].try_into().expect("Неправильный размер среза"));
    // Выполняем 32 раунда шифрования, используя раундовые ключи
    for i in 0..32 {
        let key = round_keys[i % 8];
        let (new_left, new_right) = feistel_round(left, right, key);
        left = new_left;
        right = new_right;
    }
    // Собираем зашифрованный блок из правой и левой половин
    let mut encrypted_block = [0u8; 8];
    encrypted_block[0..4].copy_from_slice(&right.to_be_bytes());
    encrypted_block[4..8].copy_from_slice(&left.to_be_bytes());
    encrypted_block
}

// Функция дешифрования блока данных
fn decrypt_block(block: [u8; 8], round_keys: &[u32; 8]) -> [u8; 8] {
    // Преобразуем последние 4 байта блока в 32-битное число для левой половины
    let mut left = u32::from_be_bytes(block[4..8].try_into().expect("Неправильный размер среза"));
    // Преобразуем первые 4 байта блока в 32-битное число для правой половины
    let mut right = u32::from_be_bytes(block[0..4].try_into().expect("Неправильный размер среза"));
    // Выполняем 32 раунда дешифрования в обратном порядке
    for i in (0..32).rev() {
        let key = round_keys[i % 8];
        let (new_right, new_left) = feistel_round(right, left, key);
        left = new_left;
        right = new_right;
    }
    // Собираем расшифрованный блок из левой и правой половин
    let mut decrypted_block = [0u8; 8];
    decrypted_block[0..4].copy_from_slice(&left.to_be_bytes());
    decrypted_block[4..8].copy_from_slice(&right.to_be_bytes());
    decrypted_block
}

// Функция для обработки файлов шифрования и дешифрования
fn process_file<P: AsRef<Path>>(input_path: P, output_path: P, round_keys: &[u32; 8], is_encrypt: bool) -> Result<(), Box<dyn Error>> {
    // Открываем входной файл для чтения
    let mut input_file = File::open(input_path)?;
    // Создаем выходной файл для записи
    let mut output_file = File::create(output_path)?;

    // Буфер для хранения данных блока
    let mut buffer = [0u8; 8];
    // Читаем данные из файла по 8 байт за раз
    while let Ok(bytes_read) = input_file.read(&mut buffer) {
        if bytes_read == 0 {
            break; 
        }
        // Обрабатываем блок (шифрование или дешифрование)
        let processed_block = if is_encrypt {
            // Если меньше 8 байт прочитано, дополняем нулями
            if bytes_read < 8 {
                for i in bytes_read..8 {
                    buffer[i] = 0;
                }
            }
            encrypt_block(buffer, round_keys)
        } else {
            // При дешифровании учитываем количество прочитанных байт
            decrypt_block(buffer, round_keys)[..bytes_read].try_into().expect("Ошибка при преобразовании расшифрованного блока")
        };
        // Записываем обработанный блок в выходной файл
        output_file.write_all(&processed_block)?;
        if bytes_read < 8 {
            break; 
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // env::set_var("RUST_BACKTRACE", "0");

    let args: Vec<String> = env::args().collect();

    let mode = &args[1];
    let input_file = &args[2];
    let output_file = &args[3];
    let key_file = &args[4];

    let is_encrypt = match mode.as_str() {
        "encrypt" => true, 
        "decrypt" => false,
        _ => {
            eprintln!("Неправильный режим работы. Доступны: 'encrypt' или 'decrypt'.");
            return Err("Неправильный режим работы".into());
        }
    };

    // Генерируем или считываем ключ
    let key_hex = if is_encrypt {
        let key = generate_random_key(); // Генерация случайного ключа
        fs::write(key_file, key.as_bytes())?; // Запись ключа в файл
        key
    } else {
        match fs::read_to_string(key_file) {
            Ok(key) => {
                // println!("Ключ: {}", key);
                key 
            }
            Err(err) => {
                eprintln!("Ошибка чтения ключа: {}", err);
                return Err(err.into());
            }
        }
    };

    // Декодируем ключ из шестнадцатеричной строки в массив байт
    let key_bytes = hex::decode(key_hex.trim())?;
    if key_bytes.len() != 32 {
        return Err("Ключ должен быть 32 байта".into());
    }

    // Преобразуем ключ в массив 32-битных чисел
    let mut round_keys = [0u32; 8];
    for i in 0..8 {
        round_keys[i] = u32::from_be_bytes(key_bytes[i * 4..std::cmp::min((i + 1) * 4, key_bytes.len())].try_into().expect("Неправильный размер среза"));

    }

    // Обрабатываем файл
    process_file(input_file, output_file, &round_keys, is_encrypt)?;

    Ok(())
}

