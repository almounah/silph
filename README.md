# SILPH: Stealthy In-Memory Local Password Harvester

![silph](silph.jpg)

**SILPH** is an open-source red team tool designed to dump LSA secrets, SAM hashes, and DCC2 credentials entirely in memory, without writing any files to disk.

Unlike its upstream project **go-secdump**, SILPH is built to be integrated into the [Orsted C2 framework](https://github.com/almounah/orsted) and is intended to run directly on a Windows host, avoiding the need to create a service via RPC.

## Usage

First clone and compile (you need `go` for that):

```bash
git clone git@github.com:almounah/silph.git
cd silph
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w"
```

Then run `silph.exe`.

```
PS C:\Users\haroun> Z:\silph.exe

███████╗██╗██╗     ██████╗ ██╗  ██╗
██╔════╝██║██║     ██╔══██╗██║  ██║
███████╗██║██║     ██████╔╝███████║
╚════██║██║██║     ██╔═══╝ ██╔══██║
███████║██║███████╗██║     ██║  ██║
╚══════╝╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝

    Stealthy In-Memory Password Harvester

  "Well… I think I wanted to be like Eris."

Usage: Z:\silph.exe [options]

  -dcc2
        dump dcc2
  -lsa
        dump lsa
  -sam
        dump sam
```

A new `silph` module will be added to [Orsted C2](https://github.com/almounah/orsted) soon. Refer to orsted documentation for usage.

## Motivation

I wanted a tool to be integrated in my C2 to dump SAM and LSA. 

The issue is I was not finding tools (or at least I missed them) that does this while respecting these two conditions:

- Don't write anything on the disk
- Don't use RPC / SMB to start the service

Plus, while documenting myself on the subject I found a very interesting article [https://g3tsyst3m.com/threat%20hunting/Detecting-SAM-registry-hive-dumps-using-Elastic!/](https://g3tsyst3m.com/threat%20hunting/Detecting-SAM-registry-hive-dumps-using-Elastic!/).

Basically the author is showing us how by activating some options, an event will tell blueteamers that SAM is getting dumped. He then piped this event into Elastic. You can see the event triggered here

[samevent][samevent.png]

The python code that generates the event provided in the article uses `RegOpenKeyEx` and `RegSaveKeyEx`.

## A Brief History of Registry Dumping

There are numerous techniques for dumping sensitive Windows registry hives. Common approaches include utilities and BOFs that save the SAM, SYSTEM, and SECURITY hives to disk using tools such as the `reg` command or custom scripts.

Another approach involves creating a Volume Shadow Copy and extracting the registry hives from the snapshot.

`go-secdump` introduced a different technique. When it was first released in 2023, it relied on a service that modified the registry DACLs to grant itself sufficient access. This allowed the service to enumerate subkeys and query their names and values, enabling the recovery of plaintext secrets.

The Windows registry APIs used for enumerating keys and values operate on registry handles rather than file-backed objects, allowing these operations to be performed without writing data to disk.

In 2025, Synacktiv submitted a pull request to Impacket introducing `regsecrets.py`, which implements a similar approach. Unlike `go-secdump`, this method avoids modifying DACLs by opening registry handles with the `REG_OPTION_BACKUP_RESTORE` flag, granting the required permissions for enumeration and querying.

`SILPH` follows this approach by using `REG_OPTION_BACKUP_RESTORE` through native NT calls resolved from `ntdll`, leveraging the [Superdeye](https://github.com/almounah/superdeye) project for indirect syscalls. Because SILPH is designed to run locally on the target system, no service creation is required, reducing potential network-based detection associated with remote tooling such as Impacket.

During testing, running SILPH under the same conditions as before did not generate additional Windows Event Log entries compared to baseline execution.

## Side Story: Why the name SILPH

**SILPH** is named after **Sylphiette** from [*Mushoku Tensei*](https://myanimelist.net/anime/39535/Mushoku_Tensei__Isekai_Ittara_Honki_Dasu).

Early in her life, Sylphiette faces isolation and bullying due to her green hair, which leads others to associate her with the feared Superd race. Rather than overcoming this through force or status, she grows through learning, perseverance, and guidance, gradually developing discipline and control.

This mirrors **SILPH’s** design philosophy: a self-contained tool that operates quietly, executes entirely in memory, and integrates seamlessly without leaving a lasting footprint.
