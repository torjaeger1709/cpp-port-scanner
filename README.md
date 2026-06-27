# C++ Network Port Scanner & Desktop GUI

**C++17** network port scanner featuring concurrent execution, raw socket scanning techniques, and a Dear ImGui desktop interface.

---

## Project Goals

This project was built primarily to explore and demonstrate practical C++ engineering concepts:
- Low-level socket programming
- Cross-platform networking implementation
- Multithreading and worker synchronization
- Desktop application development with Dear ImGui
- Raw TCP packet construction

---

## Previews

### Desktop GUI
![Desktop Preview](assets/gui_preview.png)

### CLI Execution
![CLI Preview](assets/cli_preview.png)

---

# Features

* Cross-platform CLI & GUI scanner (Windows & Linux)
* Dear ImGui desktop application (Windows GUI: DirectX 11, Linux GUI: OpenGL 3)
* Layered architecture (Separated scanning engine and GUI)
* Concurrent scanning using a custom thread pool
* TCP Connect scanning
* SYN / FIN / NULL / XMAS raw scans (Linux fully supported; Windows requires Npcap)
* Basic banner grabbing
* CIDR subnet scanning
* JSON / CSV / XML report export
* Scan cancellation token support
* WSAPoll / poll asynchronous I/O multiplexing

---

# Project Architecture

The project builds two executables that share the same scanning engine.

```mermaid
graph TD
    CLI["port_scanner (CLI)"] --> Engine
    GUI["port_scanner_gui"] --> Controller
    Controller --> Engine
    Engine --> ThreadPool
    ThreadPool --> Network["Sockets / WSAPoll / poll"]
```

## Layered Architecture

### Model

Responsible for:

* TCP/UDP scanning
* Raw socket packet construction
* Banner grabbing
* Export pipeline
* Thread pool scheduling

Location:

```text
src/scanner_engine.cpp
```

---

### Controller

Responsible for:

* Launching scan workers
* Progress updates
* Scan cancellation
* Thread synchronization

Location:

```text
src/scan_controller.cpp
```

---

### View

Responsible for:

* Dear ImGui rendering
* Interactive scan configuration
* Live console
* Result tables
* Dynamic layouts

Location:

```text
src/gui_view.cpp
```

---

# Supported Features

| Feature          | CLI | GUI |
| ---------------- | --- | --- |
| Windows          | ✅   | ✅   |
| Linux            | ✅   | ✅   |
| TCP Connect Scan | ✅   | ✅   |
| SYN Scan         | ✅   | ✅   |
| FIN Scan         | ✅   | ✅   |
| NULL Scan        | ✅   | ✅   |
| XMAS Scan        | ✅   | ✅   |
| Banner Grabbing  | ✅   | ✅   |
| CIDR Scan        | ✅   | ✅   |
| JSON Export      | ✅   | ✅   |
| CSV Export       | ✅   | ✅   |
| XML Export       | ✅   | ✅   |

---

# Engineering Notes

### Asynchronous UI Execution

Scanning tasks run on background worker threads so that the interface window continues processing user input and redrawing during scans.

### Thread Synchronization

The scanning engine uses mutex locking and atomic counters to safely manage concurrent access across worker threads.

### Graceful Shutdown

Closing the application during an active scan signals cancellation tokens, waits for worker threads to finish, and releases resources safely.

### Networking Implementation

Platform-specific socket implementations are isolated where possible to support both Winsock and POSIX sockets.

---

# Dependencies

The project keeps third-party dependencies minimal to simplify cross-platform builds:

| Dependency | Purpose | Management / Installation |
| :--- | :--- | :--- |
| **Dear ImGui** (v1.90.1) | Desktop GUI UI framework | Automatically fetched and compiled via CMake `FetchContent` |
| **SDL2** | Windowing and event handling (Linux GUI) | System package (`libsdl2-dev` on Ubuntu/Debian) |
| **OpenGL 3.3** | Graphics rendering backend (Linux GUI) | System package (`libgl1-mesa-dev` on Ubuntu/Debian) |
| **DirectX 11 & Win32 SDK** | Graphics rendering backend (Windows GUI) | Included in Windows SDK / Visual Studio C++ toolchain |
| **Winsock2 (`ws2_32`) / POSIX Sockets** | Core network TCP/UDP scanning | Native OS system libraries |

---

# Building

## Windows

Requirements

* Visual Studio 2019 or newer
* Desktop Development with C++
* CMake

```powershell
cmake -B build -S .

cmake --build build --config Release
```

Generated binaries

```text
build/
├── port_scanner.exe
└── port_scanner_gui.exe
```

---

## Linux

Install dependencies

```bash
sudo apt update

sudo apt install build-essential cmake git libsdl2-dev libgl1-mesa-dev
```

Build

```bash
cmake -B build -S .

cmake --build build -j$(nproc)
```

> **Note for WSL users working on Windows mounted drives (`/mnt/c`, `/mnt/d`):** To avoid NTFS file permission errors, specify a build path inside the Linux filesystem instead: `cmake -B ~/build_scanner -S .`

Generated binaries

```text
build/
├── port_scanner
└── port_scanner_gui
```

---

# Usage

## Launch GUI

### Windows
```powershell
.\build\port_scanner_gui.exe
```

### Linux
```bash
./build/port_scanner_gui
```

Steps

1. Enter an IP address, hostname, or CIDR range.
2. Specify target ports.
3. Select the scan method.
4. Configure thread count.
5. Start the scan.

---

## CLI Examples

TCP Connect Scan

```bash
./build/port_scanner \
-t scanme.nmap.org \
-p 22,80,443 \
-o result.json
```

Subnet Scan

```bash
./build/port_scanner \
-t 192.168.1.0/24 \
-p 80 \
--threads 200 \
--timeout 500
```

Linux SYN Scan

```bash
sudo ./build/port_scanner \
-t 10.0.0.1 \
-p 1-1024 \
-sS \
-o report.csv
```

---

# Project Structure

```text
.
├── assets/
├── include/
├── src/
│   ├── scanner_engine.cpp
│   ├── scan_controller.cpp
│   ├── gui_view.cpp
│   └── ...
├── third_party/
├── CMakeLists.txt
└── README.md
```

---

# Technical Limitations

## Windows Raw Socket Restrictions

Windows restricts custom TCP packet transmission through raw sockets. True SYN/FIN/NULL/XMAS scans require Npcap. Otherwise, the scanner automatically falls back to TCP Connect mode.

---

## RFC 793 Compatibility

FIN, NULL and XMAS scans rely on RFC 793 behavior. Some operating systems—especially Windows—do not fully implement this behavior, reducing the reliability of these scan techniques.

---

# License

This project is licensed under the MIT License.

---

## Contributing

Contributions, issues, and suggestions are welcome.
