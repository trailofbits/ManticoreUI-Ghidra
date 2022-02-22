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

	public MUILogProvider(PluginTool tool, String name) {
		super(tool, name, name);
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

		Msg.info(this, "ADDLOGTAB");

		MUILogContentComponent newTabContent = new MUILogContentComponent(manticoreRunner);
		manticoreRunner.setLogUIElems(newTabContent);

		logTabPane.add(
			ZonedDateTime.now(ZoneId.systemDefault())
					.format(DateTimeFormatter.ofPattern("HH:mm:ss")),
			newTabContent);
		logTabPane.setTabComponentAt(
			logTabPane.getTabCount() - 1, new MUILogTabComponent(logTabPane, this));
		logTabPane.setSelectedIndex(logTabPane.getTabCount() - 1);
		newTabContent.requestFocusInWindow();

		fetchLogs(manticoreRunner);
		MUIStateListProvider.changeRunner(manticoreRunner);

	}

	private void fetchLogs(ManticoreRunner manticoreRunner) {

		SwingWorker sw = new SwingWorker() {

			@Override
			protected Object doInBackground() throws Exception {
				manticoreRunner.getLogText()
						.append("Manticore process started..." + System.lineSeparator());
				Msg.info(this, "START FETCH");
				boolean waiting = true;
				long prevTime = Instant.now().getEpochSecond();
				Msg.info(this, waiting);
				Msg.info(this, prevTime);
				while (waiting) {
					if (Instant.now().getEpochSecond() - 1 > prevTime) {
						prevTime = Instant.now().getEpochSecond();
						Msg.info(this, "wtf");
						waiting = !manticoreRunner.getHasStarted();
						Msg.info(this, waiting);
						Msg.info(this, manticoreRunner.getHasStarted());

					}
				} // wait until started
				Msg.info(this, "real start fetch");

				prevTime = Instant.now().getEpochSecond();
				Msg.info(this, prevTime);
				while (manticoreRunner.getIsRunning()) {
					if (Instant.now().getEpochSecond() - 1 > prevTime) {
						Msg.info(this, "legit fetched wow");
						Msg.info(this, prevTime);

						manticoreRunner.fetchMessageLogs();
						manticoreRunner.fetchStateList();
						manticoreRunner.fetchIsRunning();
						prevTime = Instant.now().getEpochSecond();
					}
				}
				return null;
			}

			@Override
			protected void done() {
				Msg.info(this, "DONE WTF");
				manticoreRunner.getStopBtn().setEnabled(false);
				manticoreRunner.fetchMessageLogs();
				manticoreRunner.fetchStateList();
				if (manticoreRunner.getWasTerminated()) {
					manticoreRunner.getLogText()
							.append(
								System.lineSeparator() + "Manticore process terminated by user.");
				}
				else {
					manticoreRunner.getLogText()
							.append(System.lineSeparator() + "Manticore process completed.");
				}
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
		if (curComp.manticoreRunner.getIsRunning()) {
			curComp.manticoreRunner.terminateManticore();
		}
		logTabPane.remove(tabIndex);
	}

	@Override
	public JComponent getComponent() {
		return logPanel;
	}
}
