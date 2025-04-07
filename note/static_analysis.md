# Static Analysis - Morph CTF

Raccogliere informazioni è essenziale nel momento in cui si deve fare reverse engineering di un binario. In questo caso, si susseguono i vari comandi eseguibili dalla shell che hanno prodotto varie informazioni importanti

- **hexdump** -C ./morph

Hexdump ci ha permesso di visualizzare i byte all'interno del file binario e mediante il flag **"-C"** siamo riusciti a concatenare il formato ASCII separato dal carattere "**|**"

*Verificare l'output del file morph_hexdump.txt per ulteriori informazioni*

La parte principale che abbiamo notato all'interno del file è questa :

```hexdump
00000f70  57 68 61 74 20 61 72 65  20 79 6f 75 20 77 61 69  |What are you wai|
00000f80  74 69 6e 67 20 66 6f 72  2c 20 67 6f 20 73 75 62  |ting for, go sub|
00000f90  6d 69 74 20 74 68 61 74  20 66 6c 61 67 21 00 00  |mit that flag!..|
00000fa0  01 1b 03 3b 4c 00 00 00  08 00 00 00 a0 f7 ff ff  |...;
```

- **file** morph

Tale comando ci ha permesso di avere queste seguenti informazioni :

```sh
morph:

- ELF 64-bit LSB shared object,
- x86-64, version 1 (SYSV), 
- dynamically linked, 
- interpreter /lib64/- ld-linux-x86-64.so.2,
- for GNU/Linux 2.6.32, 
- BuildID[sha1]=1c81eb4bc8b981ed39ef79801d6fef03d4d81056, 
- stripped

```

## 🗂️ Significato Dettagliato

### 🔹 **ELF** – *Executable and Linkable Format*

- Formato standard per file binari su sistemi Unix/Linux.
- Può rappresentare:
  - File eseguibili
  - Librerie condivise (`.so`)
  - File oggetto (compilati ma non eseguibili)
  - Core dump

### 🔹 **64-bit**

- Il file è destinato ad architetture a **64 bit**.
- Supporta:
  - Maggiore spazio di indirizzamento
  - Registri a 64 bit
- **Incompatibile** con sistemi a 32 bit.

### 🔹 **LSB** – *Least Significant Byte first*

- Indica l'**endianness**: ordine dei byte nei dati multibyte.
- **Little Endian**:
  - Il **byte meno significativo** viene memorizzato per primo.
  - Comune su CPU **x86_64** (Intel, AMD).

### 🔹 **shared object**

- È una **libreria dinamica** (`.so`):
  - Non è eseguibile direttamente.
  - Può essere **caricata da altri programmi a runtime**.
- Utilizzata per:
  - Condividere codice tra più programmi.
  - Risparmiare memoria e tempo di compilazione.

- **ldd** morph

Tale comando permette di verificare quali sono le dipendenze di questo programma binario eseguibile.
Infatti, l'output in questione è :

```sh
        linux-vdso.so.1 (0x00007ffc8d3f5000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9586a81000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f9586e89000)
```

### 1. `linux-vdso.so.1`

**Cos'è:**

`linux-vdso.so.1` è un **oggetto condiviso virtuale** (*Virtual Dynamic Shared Object* o vDSO) fornito dal kernel Linux. A differenza delle librerie tradizionali, non esiste come file fisico nel filesystem, ma viene mappato direttamente nello spazio di indirizzamento di ogni processo. citeturn0search0

**Scopo:**

Il vDSO consente l'esecuzione di alcune chiamate di sistema direttamente in spazio utente, evitando il passaggio al kernel e migliorando le prestazioni. Ad esempio, funzioni come `gettimeofday()` possono essere eseguite più rapidamente tramite il vDSO. citeturn0search1

### 2. `libc.so.6`

**Cos'è:**

`libc.so.6` è la **GNU C Library (glibc)**, la libreria standard del linguaggio C su sistemi Linux. Fornisce implementazioni per chiamate di sistema e funzioni di libreria standard come `printf()`, `malloc()`, e `open()`. Il suffisso `.6` indica la versione dell'interfaccia binaria (ABI) della libreria. citeturn0search4

**Scopo:**

Questa libreria è essenziale per il funzionamento della maggior parte dei programmi su Linux, poiché offre le funzionalità di base necessarie per le operazioni di input/output, gestione della memoria e altre operazioni fondamentali.

### 3. `/lib64/ld-linux-x86-64.so.2`

**Cos'è:**

Questo è il **linker dinamico** o **loader** per architetture x86_64. È responsabile del caricamento delle librerie condivise richieste da un programma al momento dell'esecuzione. Quando si esegue un programma, il kernel utilizza questo linker per risolvere e caricare le dipendenze dinamiche del programma. citeturn0search2

**Scopo:**

Garantisce che tutte le librerie necessarie siano correttamente caricate in memoria e che i simboli richiesti dal programma siano risolti, permettendo al programma di funzionare correttamente.

---

- **readelf** -h morph / **readelf** -a morph

Tale comando permette di vedere tutte le informazioni relative all'Header del file ELF

```sh
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x7a0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          8504 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         27
  Section header string table index: 26
```

```bash
readelf -a file
```

Mostra la **sezione dinamica (Dynamic Section)** di un file ELF. Si tratta di **una tabella contenente informazioni necessarie per il linking dinamico** a runtime. Vediamola nel dettaglio e poi osserviamo cosa c’è di interessante.

---

#### 🧩 Cos'è la *Dynamic Section*?

La *sezione dinamica* è presente nei binari ELF che utilizzano **linking dinamico** (tipico per gli eseguibili moderni e per le shared libraries `.so`). Viene letta dal **dynamic linker** (es. `ld-linux-x86-64.so.2`) per sapere:

- quali librerie caricare
- quali simboli risolvere
- dove sono le tabelle simboliche e di relocazione
- se il file è PIE, ha `bind-now`, ecc.

---

##### 📘 Spiegazione delle voci più rilevanti

| Tag                        | Significato |
|---------------------------|-------------|
| `0x00000001 (NEEDED)`     | Il binario dipende dalla libreria **`libc.so.6`** |
| `0x0000000c (INIT)`       | Indirizzo della funzione di inizializzazione (chiamata prima del `main`) |
| `0x0000000d (FINI)`       | Funzione di finalizzazione (chiamata alla fine) |
| `INIT_ARRAY` / `FINI_ARRAY` | Liste di funzioni da eseguire all'inizio/fine del programma |
| `GNU_HASH`, `SYMTAB`, `STRTAB` | Tabelle usate per la risoluzione simbolica |
| `RELA`, `RELASZ`, `RELAENT` | Tabelle di **relocazione** con addendi, necessarie per correggere indirizzi a runtime |
| `PLTGOT`                  | Global Offset Table per il Procedure Linkage Table (usata in PLT/GOT per chiamate a funzioni dinamiche) |
| `FLAGS` - `BIND_NOW`      | Forza la **risoluzione immediata** di tutti i simboli (non lazy loading) |
| `FLAGS_1` - `NOW PIE`     | Il binario è **Position-Independent Executable (PIE)**: può essere caricato a un indirizzo variabile in memoria, utile per ASLR |
| `VERNEED`, `VERSYM`       | Tabelle di versionamento dei simboli (versioning delle librerie dinamiche) |

---

##### 🔍 Cosa c’è di particolare in questo caso?

###### 1. **Presenza di `BIND_NOW`**

- Questo indica che tutti i simboli delle librerie vengono **risolti immediatamente** al caricamento.
- Più sicuro contro certi tipi di attacchi (come GOT overwrite), ma può rallentare l'avvio.

###### 2. **Il binario è un PIE (`NOW PIE`)**

- Significa che è un **eseguibile position-independent**, come le shared libraries.
- Questo rende il binario **ASLR-friendly** (Address Space Layout Randomization), aumentando la sicurezza.

###### 3. **Una sola libreria dinamica richiesta (`libc.so.6`)**

- Il binario è minimale, dipende solo dalla **libreria C standard**.
- Potrebbe essere un test program, un payload o un componente scritto in C con poche dipendenze.

###### 4. **Sezioni INIT e INIT_ARRAY**

- Questi campi indicano la presenza di **funzioni di inizializzazione**, chiamate automaticamente dal linker **prima del `main()`**.
- Potrebbero contenere codice di setup, o in alcuni casi, anche payload/malware se il binario è sospetto.

- **objdump** -d morph | head

Tale comando riesce a leggere le varie istruzioni che sono state prodotte nel linguaggio assembly.

*Nota.* Nel file morph_objdump.txt è stato il codice disassemblato per intero, tutte le sezioni sono state esplorate

- **strace** ./morph

Tale comando permette di chiamare una libreria, **strace**  traccia le chiamate di sistema.

Per fare un esempio, se si desidera stampare qualcosa sullo schermo, si utilizzerà la  funzione printf  o  puts  della libreria standard  libc ; verrà effettuata una chiamata di sistema denominata write per stampare effettivamente qualcosa sullo schermo.

**Nota** Vedere il file morph_strace.txt per ulteriori informazioni

- **strings** ./morph

Tale comando permette di recuperare tutti caratteri che sono scritti all'interno del file binario in chiaro

**Nota** Verificare il file morph_strings.txt
