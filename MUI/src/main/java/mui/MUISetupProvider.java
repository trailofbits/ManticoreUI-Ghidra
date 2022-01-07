package mui;

import docking.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;

import javax.swing.*;

public class MUISetupProvider extends ComponentProviderAdapter {

	private Program program;

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

	private JPanel formPanel;
	private HashMap<String, Object> formOptions;
//	private HashMap<String, JPanel> inputRows;
	
	public MUISetupProvider(PluginTool tool, String name, MUILogProvider log) {
		super(tool, name, name);
		setLogProvider(log);
		buildFormPanel();
		buildMainPanel();
		setTitle("MUI Setup");
		setDefaultWindowPosition(WindowPosition.WINDOW);
		setVisible(true);
	}

	private void setLogProvider(MUILogProvider log) {
		logProvider = log;
	}

	private void buildFormPanel() throws UnsupportedOperationException {
		formPanel = new JPanel();
		formPanel.setLayout(new BoxLayout(formPanel, BoxLayout.Y_AXIS));
		formPanel.setMinimumSize(new Dimension(800,500));
		formOptions = new HashMap<>();
		
		for (Entry<String, Map<String, Object>[]> option:MUISettings.SETTINGS.get("NATIVE_RUN_SETTINGS").entrySet()) {
			String name = option.getKey();
			Map<String, Object> prop = option.getValue()[0];
			Map<String, Object> extra = option.getValue()[1];
			
			String title = (String) prop.get("title");
			
			JPanel inputRow = new JPanel(new GridBagLayout());
		//	inputRows.put(name, inputRow);
			inputRow.setMinimumSize(new Dimension(800,100));
			GridBagConstraints inputRowConstraints = new GridBagConstraints();
			inputRowConstraints.fill = GridBagConstraints.HORIZONTAL;
			
			inputRowConstraints.gridx=0;
			inputRowConstraints.gridwidth=3;
			inputRowConstraints.gridy=0;
			inputRowConstraints.gridheight=1;
			inputRowConstraints.weightx = 1.0;
			inputRowConstraints.weighty = 1.0;
			inputRow.add(new JLabel(title), inputRowConstraints);
			
			JTextField entry = new JTextField();
			
			if(extra.containsKey("is_dir_path") && (Boolean) extra.get("is_dir_path")) {
				entry.setText((String) prop.get("default"));
				inputRowConstraints.gridx=3;
				inputRowConstraints.gridwidth=3;
				inputRow.add(entry, inputRowConstraints);
				
				JFileChooser chooser = new JFileChooser();
				chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				chooser.setDialogTitle("Set Workspace Folder");
				
				JButton selectButton = new JButton("Select...");
				selectButton.addActionListener(new ActionListener() {

					@Override
					public void actionPerformed(ActionEvent e) {
						int returnVal = chooser.showOpenDialog(null);
						if(returnVal==JFileChooser.APPROVE_OPTION) {
							try {
								String path = chooser.getSelectedFile().getCanonicalPath();
								entry.setText(path);
							} catch (IOException e1) {
								e1.printStackTrace();
							}
						}
					}
					
				});
				
				inputRowConstraints.gridx=6;
				inputRowConstraints.gridwidth=1;
				inputRow.add(selectButton, inputRowConstraints);
				
				formOptions.put(name, entry);
			} else if (prop.get("type") == "string" || prop.get("type") == "number") {
				entry.setText(prop.get("default").toString());
				inputRowConstraints.gridx=3;
				inputRowConstraints.gridwidth=4;
				inputRow.add(entry, inputRowConstraints);
				
				formOptions.put(name, entry);
			} else if (prop.get("type") == "array") {
				// TODO: doesn't handle default param for arrays, but not needed as part of sensible defaults for running manticore on native binaries
				ArrayList<JTextField> arr_tfs = new ArrayList<JTextField>();
				
				JButton add_tf = new JButton("+");
				add_tf.addActionListener(new ActionListener() {

					@Override
					public void actionPerformed(ActionEvent e) {
						Msg.info(this,String.format("clicked + and and constraintgridy is %s and inputRow is ",inputRowConstraints.gridy)+inputRow.toString());
						inputRowConstraints.gridy++;
						arr_tfs.add(new JTextField());
						inputRow.add(arr_tfs.get(arr_tfs.size()-1), inputRowConstraints);
					}
					
				});
				inputRowConstraints.gridx=3;
				inputRowConstraints.gridwidth=4;
				inputRow.add(add_tf,inputRowConstraints);
				
				for(Object element: (ArrayList) prop.get("default")) {
					inputRowConstraints.gridy++;
					arr_tfs.add(new JTextField(element.toString()));
					inputRow.add(arr_tfs.get(arr_tfs.size()-1), inputRowConstraints);
				}
				
				formOptions.put(name, arr_tfs);
				
				
			} else {
				// TODO: to achieve parity with Binja MUI, type==boolean must be supported, but not needed as part of sensible defaults for running manticore on native binaries
				throw new UnsupportedOperationException(String.format("[ERROR] Cannot create input row for %s with the type %s", name, prop.get("type")));
			}
			
			Msg.info(this, formOptions.toString());
			formPanel.add(inputRow);
			
		}
	}
	
	private void buildMainPanel() {
		mainPanel = new JPanel(new BorderLayout());
		mainPanel.setMinimumSize(new Dimension(900, 500));

		
		mainPanel.add(formPanel, BorderLayout.CENTER);
		
		
		runBtn = new JButton("Run");
		runBtn.addActionListener(
			new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					if (manticoreExePath.length() == 0) {
						logProvider.noManticoreBinary();
					}
					else {
						logProvider.runMUI(
							parseCommand(manticoreExePath.concat(manticoreArgsArea.getText())));
					}
				}
			});

		

//		inputPanel = new JPanel(new GridBagLayout());
//
//		inputPanelConstraints = new GridBagConstraints();
//		inputPanelConstraints.fill = GridBagConstraints.BOTH;
//
//		inputPanelConstraints.gridx = 0;
//		inputPanelConstraints.gridy = 0;
//		inputPanelConstraints.weightx = 0.25;
//		inputPanelConstraints.gridwidth = 1;
//		inputPanel.add(new JLabel("Program Path:"), inputPanelConstraints);
//
//		if (programPath == null) {
//			programPath = "";
//		}
//		programPathLbl = new JLabel(programPath);
//		inputPanelConstraints.gridx = 1;
//		inputPanelConstraints.gridy = 0;
//		inputPanelConstraints.weightx = 0.75;
//		inputPanelConstraints.gridwidth = 3;
//		inputPanel.add(programPathLbl, inputPanelConstraints);
//
//		JLabel manticoreArgsLbl = new JLabel("Manticore Args:");
//		inputPanelConstraints.gridx = 0;
//		inputPanelConstraints.gridy = 1;
//		inputPanelConstraints.weightx = 0.0;
//		inputPanelConstraints.gridwidth = 4;
//		inputPanel.add(manticoreArgsLbl, inputPanelConstraints);
//
//		manticoreArgsArea = new JTextArea();
//		manticoreArgsArea.setToolTipText("Enter arguments as you would in CLI");
//		manticoreArgsArea.setLineWrap(true);
//		manticoreArgsArea.setWrapStyleWord(true);
//		inputPanelConstraints.gridx = 0;
//		inputPanelConstraints.gridy = 2;
//		inputPanelConstraints.ipady = 50;
//		inputPanelConstraints.weightx = 0.0;
//		inputPanelConstraints.gridwidth = 4;
//		inputPanel.add(manticoreArgsArea, inputPanelConstraints);
//		
//		try {
//			if (!Application.isInitialized()) {
//				Application.initializeApplication(
//					new GhidraApplicationLayout(), new ApplicationConfiguration());
//			}
//			manticoreExePath = Application.getOSFile("manticore").getAbsolutePath().concat(" ");
//		}
//		catch (Exception e) {
//			manticoreExePath = "";
//		}
//		inputPanelConstraints.gridx = 0;
//		inputPanelConstraints.gridy = 3;
//		inputPanelConstraints.weightx = 0.9;
//		inputPanelConstraints.anchor = GridBagConstraints.SOUTH;
//		inputPanelConstraints.ipady = 0;
//		inputPanelConstraints.gridwidth = 4;
//		inputPanelConstraints.insets = new Insets(10, 0, 0, 0);
//		inputPanel.add(runBtn, inputPanelConstraints);
//
//		mainPanel.add(inputPanel, mainPanelConstraints);
	}

	public void setProgram(Program p) {
		program = p;
		programPath = program.getExecutablePath();
//		if (programPathLbl != null) { // if mainPanel built before program activated
//			programPathLbl.setText(programPath);
//		}
//		manticoreArgsArea.setText("--workspace tmpMUI ".concat(programPath));
	}

	/**
	 * Tokenizes a string by spaces, but takes into account spaces embedded in quotes or escaped
	 * spaces. Should no longer be required once UI for args is implemented.
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
			}
			else if (WORD_DELIMITERS.contains(c) && quote == 0) {
				words.add(wordBuilder.toString());
				wordBuilder.setLength(0);
			}
			else if (quote == 0 && QUOTE_CHARACTERS.contains(c)) {
				quote = c;
			}
			else if (quote == c) {
				quote = 0;
			}
			else {
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
