# Реализация алгоритма шифрования "Магма" - ГОСТ 34.12─2015

---

**Как использовать**:

```
$> .\magma.exe <mode> <input file> <output file> <keyfile>
```

**Пример использования**:

_Шифрование_:

```
$> .\magma.exe encrypt input.txt encrypted.bin keyfile.txt
```

_Дешифрование_

```
.\magma.exe decrypt encrypted.bin decrypted.txt keyfile.txt
```

---

P.S.

> Не уверен, но если запускать бинарник Rust, то потребуются некоторые библиотеки, которые берутся из VC_redist.x64 или VC_redist.x86
