# TuxLoad

Local project for recording and replaying 64-bit Oracle Tuxedo clients, then running performance tests. This folder is not a git repository.

The first tool is a read-only discovery script. It answers the four facts the recorder and the replay engine depend on. Run it on the machines that have the application and Tuxedo, then bring the report back before the engine is built. The engine has to link the 64-bit Tuxedo client libraries that this script finds.

## What the script answers

| Question | What it looks for |
|---|---|
| 1. Tuxedo version and operating system | Windows version on the machine where you run it. Tuxedo version from the library version resource, the install directory name, or `tmadmin -v` on Unix. |
| 2. Client mode and language | `WSNADDR` means a Workstation client. `TUXCONFIG` without `WSNADDR` means a native client. `TOBJADDR` means CORBA. A `jolt.jar` or Jolt DLL means Java. The executable header shows 32-bit, 64-bit, native, or .NET. |
| 3. Buffer types, conversations, transactions | `FLDTBLDIR32` and `*.fml32` mean FML32. `VIEWDIR32` means VIEW32. Inside the executable, `tpconnect` means conversations and `tpbegin` / `tpcommit` means transactions. |
| 4. 64-bit libraries and field tables | Bitness of `libwsc.dll` (Workstation) and `libtux.dll` (native), and whether the field table files can be opened. |

You can see the same facts by hand: the start script for the application, File Properties on `libwsc.dll`, and `tmadmin -v` plus `uname -a` on the server. The script collects them in one pass and writes a report with a confidence level per answer.

## Where to run it

1. On the Windows machine where the 64-bit application is installed (the machine LoadRunner could not record). Start the application first if you can. A running process lets the script see which Tuxedo DLL is actually loaded.
2. On the Tuxedo server (Linux or AIX), using the Unix script, from the account that already has `TUXDIR` set.

## Windows

Open PowerShell on the application machine. Copy `discovery\Discover-Tuxedo.ps1` there if the application is not on this PC.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\discovery\Discover-Tuxedo.ps1 -AppPath "D:\Apps\Billing\billing.exe" -StartupScript "D:\Apps\Billing\start-billing.cmd"
```

`-StartupScript` is the `.bat` or `.cmd` that sets `TUXDIR`, `WSNADDR`, and `FLDTBLDIR32`. If you omit it, the script still reads `.bat` and `.cmd` files next to the executable, plus the current environment.

If Tuxedo is installed but `TUXDIR` is not set, pass it:

```powershell
-TuxDir "D:\oracle\tuxedo12.2.2.0.0"
```

The report is written to `.\tuxload-discovery-output\tuxload-discovery.txt`. The scan can take a minute while it checks install folders and the running application.

The script does not change the machine and does not log on to Tuxedo. If it finds a `WSNADDR` value, it checks whether that host and port accept a TCP connection.

## Unix or AIX server

Copy `discovery\discover-tuxedo.sh` to the server and run it with the Tuxedo environment already loaded:

```sh
sh discover-tuxedo.sh
sh discover-tuxedo.sh /path/to/client/app /tmp/tuxload-discovery-server.txt
```

`tmadmin -v` is used only to print the version. It should exit on its own. If it waits for input, press Ctrl+C and send the partial report anyway.

## What to do with the report

Review `tuxload-discovery.txt` before sharing it. It contains computer names, host names, and file paths. It does not keep values whose names look like passwords.

Copy the Windows report and the server report into this folder when you have them. Those two files decide whether the replay engine is built against the 64-bit Workstation library, and which buffer types the recorder must support.

## Layout

```
TuxLoad/
  discovery/Discover-Tuxedo.ps1    Windows application machine
  discovery/discover-tuxedo.sh     Unix or AIX Tuxedo server
  examples/sample-inquiry.yaml     Target shape of a replay script (not runnable yet)
```

`examples/sample-inquiry.yaml` shows the script we will replay after the libraries are confirmed. Nothing in this folder records or drives Tuxedo yet.
