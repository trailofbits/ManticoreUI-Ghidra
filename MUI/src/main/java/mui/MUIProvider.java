package mui;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import java.awt.*;
import java.awt.event.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;
import java.util.List;

import docking.*;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class MUIProvider extends ComponentProviderAdapter {

	private Program program;
	private DockingAction action;

	private JPanel mainPanel;
	private GridBagConstraints mainPanelConstraints;

	private JPanel inputPanel;
	private GridBagConstraints inputPanelConstraints;
	private JTextArea manticoreArgsArea;
	private JLabel programPathLbl;
	private String programPath;
	private JButton runBtn;
	private String manticoreExePath;

	private MUILogProvider logProvider;
	private Boolean isStopped; // stopped meaning forcefully stopped by user

	public MUIProvider(PluginTool tool, String name, MUILogProvider log) {
		super(tool, name, name);
		setLogProvider(log);
		buildMainPanel();
		setTitle("MUI");
		setDefaultWindowPosition(WindowPosition.WINDOW);
		setVisible(true);
	}

	private void setLogProvider(MUILogProvider log) {
		logProvider = log;
	}

	private void buildMainPanel() {
		mainPanel = new JPanel(new GridBagLayout());
		mainPanel.setMinimumSize(new Dimension(500, 500));

		mainPanelConstraints = new GridBagConstraints();
		mainPanelConstraints.fill = GridBagConstraints.BOTH;
		mainPanelConstraints.gridwidth = GridBagConstraints.REMAINDER;
		mainPanelConstraints.weightx = 0.9;
		mainPanelConstraints.weighty = 0.9;

		inputPanel = new JPanel(new GridBagLayout());
		TitledBorder borderInp = BorderFactory.createTitledBorder("MUI Setup");
		borderInp.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
		inputPanel.setBorder(borderInp);
		inputPanelConstraints = new GridBagConstraints();
		inputPanelConstraints.fill = GridBagConstraints.BOTH;

		inputPanelConstraints.gridx = 0;
		inputPanelConstraints.gridy = 0;
		inputPanelConstraints.weightx = 0.25;
		inputPanelConstraints.gridwidth = 1;
		inputPanel.add(new JLabel("Program Path:"), inputPanelConstraints);

		if (programPath == null) {
			programPath = "";
		}
		programPathLbl = new JLabel(programPath);
		inputPanelConstraints.gridx = 1;
		inputPanelConstraints.gridy = 0;
		inputPanelConstraints.weightx = 0.75;
		inputPanelConstraints.gridwidth = 3;
		inputPanel.add(programPathLbl, inputPanelConstraints);

		JLabel manticoreArgsLbl = new JLabel("Manticore Args:");
		inputPanelConstraints.gridx = 0;
		inputPanelConstraints.gridy = 1;
		inputPanelConstraints.weightx = 0.0;
		inputPanelConstraints.gridwidth = 4;
		inputPanel.add(manticoreArgsLbl, inputPanelConstraints);

		manticoreArgsArea = new JTextArea();
		manticoreArgsArea.setToolTipText("Enter arguments as you would in CLI");
		manticoreArgsArea.setLineWrap(true);
		manticoreArgsArea.setWrapStyleWord(true);
		inputPanelConstraints.gridx = 0;
		inputPanelConstraints.gridy = 2;
		inputPanelConstraints.ipady = 50;
		inputPanelConstraints.weightx = 0.0;
		inputPanelConstraints.gridwidth = 4;
		inputPanel.add(manticoreArgsArea, inputPanelConstraints);

		try {
			if (!Application.isInitialized()) {
				Application.initializeApplication(new GhidraApplicationLayout(), new ApplicationConfiguration());
			}
			manticoreExePath = Application.getOSFile("manticore").getAbsolutePath().concat(" ");
		} catch (Exception e) {
			manticoreExePath = "manticore ";
		}
		runBtn = new JButton("Run");
		runBtn.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (manticoreExePath.length() == 0) {
					logProvider.appendLog(
							"ERROR: Packaged manticore binary not found! Attempting with \"manticore\" in PATH...");
				}
				callManticore(parseCommand(manticoreExePath.concat(manticoreArgsArea.getText())));

			}

		});
		inputPanelConstraints.gridx = 0;
		inputPanelConstraints.gridy = 3;
		inputPanelConstraints.weightx = 0.9;
		inputPanelConstraints.anchor = GridBagConstraints.SOUTH;
		inputPanelConstraints.ipady = 0;
		inputPanelConstraints.gridwidth = 4;
		inputPanelConstraints.insets = new Insets(10, 0, 0, 0);
		inputPanel.add(runBtn, inputPanelConstraints);

		mainPanel.add(inputPanel, mainPanelConstraints);

		isStopped = false;

	}

	public void stopManticore() {
		logProvider.updateButtonStatus(false);
		isStopped = true;
	}

	private void callManticore(String[] manticoreArgs) {
		isStopped = false;
		logProvider.updateButtonStatus(true);
		runBtn.setEnabled(false);
		SwingWorker sw = new SwingWorker() {
			@Override
			protected Object doInBackground() throws Exception {
				ProcessBuilder pb = new ProcessBuilder(manticoreArgs);
				try {
					Process p = pb.start();
					BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
					String line = "";
					while ((line = reader.readLine()) != null && !isStopped) {
						logProvider.appendLog(line);
					}
					if (isStopped) {
						p.destroy();
					} else {
						p.waitFor();
					}
					reader.close();

				} catch (Exception e1) {
					e1.printStackTrace();
				}
				return null;
			}

			@Override
			protected void done() {
				logProvider.updateButtonStatus(false);
				runBtn.setEnabled(true);
				if (isStopped) {
					logProvider.appendLog("Manticore stopped by user.");
				} else {
					logProvider.appendLog("Manticore execution complete.");
				}

			}
		};
		sw.execute();

	}

	public void setProgram(Program p) {
		program = p;
		programPath = program.getExecutablePath();
		if (programPathLbl != null) { // if mainPanel built before program activated
			programPathLbl.setText(programPath);
		}
		manticoreArgsArea.setText("--workspace tmpMUI ".concat(programPath));

	}

	/**
	 * Tokenizes a string by spaces, but takes into account spaces embedded in
	 * quotes or escaped spaces. Should no longer be required once UI for args is
	 * implemented.
	 */
	public String[] parseCommand(String string) {
		final List<Character> WORD_DELIMITERS = Arrays.asList(' ', '\t');
		final List<Character> QUOTE_CHARACTERS = Arrays.asList('"', '\'');
		final char ESCAPE_CHARACTER = '\\';

		StringBuilder wordBuilder = new StringBuilder();
		List<String> words = new ArrayList<>();
		char quote = 0;

		for (int i = 0; i < string.length(); i++) {
			char c = string.charAt(i);

			if (c == ESCAPE_CHARACTER && i + 1 < string.length()) {
				wordBuilder.append(string.charAt(++i));
			} else if (WORD_DELIMITERS.contains(c) && quote == 0) {
				words.add(wordBuilder.toString());
				wordBuilder.setLength(0);
			} else if (quote == 0 && QUOTE_CHARACTERS.contains(c)) {
				quote = c;
			} else if (quote == c) {
				quote = 0;
			} else {
				wordBuilder.append(c);
			}
		}

		if (wordBuilder.length() > 0) {
			words.add(wordBuilder.toString());
		}

		return words.toArray(new String[0]);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

}
