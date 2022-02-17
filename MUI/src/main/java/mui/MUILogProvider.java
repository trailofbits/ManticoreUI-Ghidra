package mui;

import docking.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import java.awt.*;
import java.io.IOException;
import java.net.Socket;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;

import javax.swing.*;

/**
 * Provides the "MUI Log" component used to display Manticore Logs. Also acts as the control center for the StateList component and for managing the different Manticore instances.
 */
public class MUILogProvider extends ComponentProviderAdapter {

	private JPanel logPanel;
	private JTabbedPane logTabPane;
	private int defPort;

	public MUILogProvider(PluginTool tool, String name) {
		super(tool, name, name);
		defPort = 3214;
		buildLogPanel();
		setTitle("MUI Log");
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setVisible(false);
	}

	/** 
	 * Builds main component panel which hosts multiple log tabs.
	 */
	private void buildLogPanel() {
		logPanel = new JPanel();
		logPanel.setLayout(new BorderLayout());
		logPanel.setMinimumSize(new Dimension(500, 300));

		logTabPane = new JTabbedPane();
		logPanel.add(logTabPane);
	}

	/**
	 * Builds and makes changes to UI elements when a user attempts to run a new instance of Manticore, and calls the function that actually creates the new Manticore process.
	 * @param programPath Path of the binary being analyzed.
	 * @param formOptions Map storing pre-selected key Manticore options.
	 * @param moreArgs Additional Manticore arguments set by the user.
	 */
	public void runMUI(String programPath,
			HashMap<String, JTextField> formOptions, String moreArgs) {
		MUILogContentComponent newTabContent = new MUILogContentComponent();

		newTabContent.MUIInstance
				.callProc(buildCommand(programPath, formOptions, moreArgs), defPort);

		logTabPane.add(
			ZonedDateTime.now(ZoneId.systemDefault())
					.format(DateTimeFormatter.ofPattern("HH:mm:ss")),
			newTabContent);
		logTabPane.setTabComponentAt(
			logTabPane.getTabCount() - 1, new MUILogTabComponent(logTabPane, this));
		logTabPane.setSelectedIndex(logTabPane.getTabCount() - 1);
		MUIStateListProvider.changeRunner(newTabContent.MUIInstance);
		newTabContent.requestFocusInWindow();

	}

	/**
	 * Structures Manticore argument data input by the user to be compatible with ProcessBuilder.
	 * @param programPath Path of the binary being analyzed.
	 * @param formOptions Map storing pre-selected key Manticore options.
	 * @param moreArgs Additional Manticore arguments set by the user.
	 * @return String array suitable to be passed to a ProcessBuilder.
	 */
	public String[] buildCommand(String programPath, HashMap<String, JTextField> formOptions,
			String moreArgs) {
		ArrayList<String> f_command = new ArrayList<String>();
		f_command.add(formOptions.get("{mcore_binary}").getText());

		for (Entry<String, JTextField> option : formOptions.entrySet()) {
			if (Arrays.asList("argv", "{mcore_binary}", "{state_server_port}")
					.contains(option.getKey()))
				continue;
			for (String arg : tokenizeArrayInput(option.getValue().getText())) {
				f_command.add("--".concat(option.getKey()));
				f_command.add(arg);
			}
		}

		f_command.addAll(Arrays.asList(tokenizeArrayInput(moreArgs)));

		f_command.add("--core.PORT");

		if (formOptions.get("{state_server_port}").getText().length() == 0) {
			defPort = 3214;
			while (!portAvailable(defPort)) {
				defPort += 2;
			}
			f_command.add(Integer.toString(defPort));
		}
		else {
			f_command.add(Integer.toString(
				Integer.parseInt(formOptions.get("{state_server_port}").getText()) - 1));
		}

		f_command.add(programPath);

		String[] argv = tokenizeArrayInput(formOptions.get("argv").getText());
		f_command.addAll(Arrays.asList(argv));
		Msg.info(this, f_command.get(0));
		return f_command.toArray(String[]::new);
	}

	/**
	 * Checks whether a port is available or already in use.
	 * @param port The port to check the availability of.
	 * @return True if the given port is available, False if it's in use.
	 */
	private boolean portAvailable(int port) {
		Socket s = null;
		try {
			s = new Socket("localhost", port);
			return false;
		}
		catch (IOException e) {
			return true;
		}
		finally {
			if (s != null) {
				try {
					s.close();
				}
				catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
	}

	/**
	 * Performs auxiliary actions when closing a tab, including stopping the Manticore instance and removing the tab component from the tab pane.
	 * @param tabIndex The index of the closed tab in the MUI Log tab pane.
	 */
	public void closeLogTab(int tabIndex) {
		MUILogContentComponent curComp =
			(MUILogContentComponent) logTabPane.getComponentAt(tabIndex);
		curComp.MUIInstance.stopProc();
		logTabPane.remove(tabIndex);
	}

	@Override
	public JComponent getComponent() {
		return logPanel;
	}
}
