# File Synchronization System (FSS)

A lightweight C-based File Synchronization System that simulates multi-process coordination between a central manager, console interface, and worker nodes.

## 📦 Project Structure

* `fss_manager.c`: Core process that oversees worker nodes and synchronization logic.
* `fss_console.c`: CLI console for user commands and system interaction.
* `worker.c`: Worker process that handles file-related operations under manager control.

## ⚙️ Features

* Multi-process communication using pipes and signals
* File synchronization simulation with worker subprocesses
* Console-based command interface
* Robust signal handling and error reporting

## 🚀 Build & Run

1. Compilation:
```bash  
   make   # Creates the executables in the bin/ folder.
   make clean # Cleans up. 
```

2. Starting Manager: 
```bash 
   ./bin/fss_manager -c config.txt -l manager.log -n 3 #This is an example run
```

3. Start Console:  
```bash
   ./bin/fss_console -l console.log #This is an example run
```

4. Test Workers:  
   Each worker is automatically called when changes are detected or with add/sync commands.

## 🛠️ Dependencies

* GCC
* Unix-based system (uses `fork()`, `kill()`, `pipe()`, etc.)

## 📁 License

MIT License

---