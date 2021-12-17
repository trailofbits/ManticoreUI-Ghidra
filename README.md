# MUI-Ghidra
MUI support for Ghidra. This is primarily a prototype repository. See the main [MUI repo](https://github.com/trailofbits/mui) for a more complete implementation.

# Usage

At its present form, MUI-Ghidra manifests as two Ghidra components named `MUI` and `MUI Log`. You may open these components via `Window -> MUI/MUI Log`.

![image](https://user-images.githubusercontent.com/29654756/146400647-2bf2d4fa-8991-4835-8b55-7f3c8d04557d.png)

### MUI
- The `MUI` component allows you to specify `manticore` args and run the command
- A workspace name (`tmpMUI`) and the program path should be pre-filled for you
- Click `Run` to execute the manticore command with your desired args

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

1. Manticore with native binary support must first be [installed](https://github.com/trailofbits/manticore/tree/5227be4244fe86fec3adf3a0f293553ac92bf1a4#installation) (eg. via `pip install "manticore[native]"`
2. Copy the zip file to the `Extensions` folder in your Ghidra directory 
3. Run Ghidra and select the extension in `File -> Install Extensions`
4. Restart Ghidra 
