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

	private boolean isFetchingLogs;

	public MUILogProvider(PluginTool tool, String name) {
		super(tool, name, name);
		isFetchingLogs = false;
		currentlyShownRunner = null;
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
	public void addLogTab(ManticoreRunner manticoreRunner) {

		MUILogContentComponent newTabContent = new MUILogContentComponent(manticoreRunner);

		logTabPane.add(
			ZonedDateTime.now(ZoneId.systemDefault())
					.format(DateTimeFormatter.ofPattern("HH:mm:ss")),
			newTabContent);
		logTabPane.setTabComponentAt(
			logTabPane.getTabCount() - 1, new MUILogTabComponent(logTabPane, this));
		logTabPane.setSelectedIndex(logTabPane.getTabCount() - 1);
		newTabContent.requestFocusInWindow();

		if (!isFetchingLogs) {
			fetchLogs();
		}

		MUIStateListProvider.changeRunner(newTabContent.MUIInstance);

	}

	private void fetchLogs() {
		
		isFetchingLogs = true;
		
		SwingWorker sw = new SwingWorker() {

			@Override
			protected Object doInBackground() throws Exception {
				long prevTime = Instant.now().getEpochSecond();
				while(isFetchingLogs) {
					if(Instant.now().getEpochSecond() - 1 > prevTime) {
						(MUILogContentComponent)logTabPane.getSelectedComponent() .fetchMessageLogs();
						currentlyShownRunner.getLogText();
					}
				}
				return null;
			}
			
		};
		
		sw.execute();
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
