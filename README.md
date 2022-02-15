# MUI-Ghidra
MUI support for Ghidra. This is primarily a prototype repository. See the main [MUI repo](https://github.com/trailofbits/mui) for a more complete implementation.

# Usage

At its present form, MUI-Ghidra manifests as three Ghidra components named `MUI Setup` (used to specify args and run Manticore), `MUI Log`, and `MUI State List` (which display Manticore output). 

1. To run manticore on the current binary, open the `MUI Setup` component via `MUI -> Run Manticore` in the menu.

![image](https://user-images.githubusercontent.com/29654756/150149215-3ade543a-b556-4cb0-b758-acd5a5b9f6d5.png)

2. Fill in manticore and program arguments in the `MUI Setup` component, and click the `Run` Button. Notably, users can specify:
- the Manticore binary used (by default, a bundled binary which requires `python3.9` on PATH is used)
- the port used by Manticore's state server (by default, an open port starting from `3215` will be allocated).

![image](https://user-images.githubusercontent.com/29654756/150147868-fc525a73-72c2-4980-be9a-d2d07fd5f423.png)

3. View log message output and a list of states and their statuses via the `MUI Log`/`MUI State List` components which will be visible on `Run`. Alternatively, you can open the components manually via `MUI -> Show Log / Show State List` in the menu. 

![image](https://user-images.githubusercontent.com/29654756/149968899-ab9b5970-0e24-462f-8c5a-2861aa3ed3ad.png)
![image](https://user-images.githubusercontent.com/29654756/149969392-4a111c5f-8cf0-45aa-93e5-e0a23ac0a869.png)


### MUI
- The `MUI Setup` component allows you to specify key `manticore` arguments
- You may add additional arguments in the `Extra Manticore Arguments` field at the bottom of the panel
- Click `Run` to execute the manticore command with your desired arguments

### MUI Log
- At present, `stdout` from `manticore` is output to the log
- You may stop the execution of manticore and clear the log with the Stop and Clear buttons on the toolbar

# Building

Build the plugin with Gradle. Built plugin will be a `zip` file in `dist` directory.

```bash
cd MUI/
GHIDRA_INSTALL_DIR=<path_to_ghidra_directory> gradle
```

# Installation

1. Ensure that Python 3.9 is installed (and that you have a `python3.9` binary). Manticore is bundled with the plugin and does not need to be separately installed, but currently requires python3.9.

  * Note: You can build this for yourself by using the [`shiv`](https://shiv.readthedocs.io/en/latest/) tool and running the following:
```sh
shiv --reproducible -c manticore -o ./os/linux_x86_64/manticore <path_to_local>/manticore[native]
```
2. Copy the zip file to the `Extensions` folder in your Ghidra directory 
3. Run Ghidra and select the extension in `File -> Install Extensions`
4. Restart Ghidra 

# Development

1. Fork and clone the repo
2. Install the [GhidraDev plugin](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/GhidraDev_README.html) in Eclipse
3. Import the project via `File -> Import -> General -> Projects from Folder or Archive`
4. Link your installation of Ghidra via `GhidraDev -> Link Ghidra`. The necessary `.project` and `.pydevproject` files will be generated for Eclipse.
5. Format your code with the included `MUI/GhidraEclipseFormatter.xml` (taken from upstream Ghidra) by running `just format` with the tool [just](https://github.com/casey/just).
6. When you first build the plugin, a protobuf compiler binary will generate the `StateOuterClass.java` file used for Manticore message & state list deserialization.
