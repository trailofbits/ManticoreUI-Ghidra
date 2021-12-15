package mui;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import java.awt.*;
import java.awt.event.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import docking.*;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import resources.ResourceManager;

public class MUIProvider extends ComponentProviderAdapter {
	
	private Program program;
	private DockingAction action;

	private JPanel mainPanel;
	private GridBagConstraints mainPanelConstraints;
	
	private JPanel inputPanel;
	private GridBagConstraints inputPanelConstraints;
	private JTextArea commandArgsArea;
	private JLabel programPathLbl;
	private String programPath = "";
	private JButton runBtn;
	private JButton stopBtn;
		
	private JPanel outputPanel;
	private GridBagConstraints outputPanelConstraints;
	private JTextArea outputArea;
	private StringBuilder logText;

	
	
	public MUIProvider(PluginTool tool, String name, Program p) {
		super(tool, name, name);
		buildMainPanel();
		setIcon(ResourceManager.loadImage("images/erase16.png"));
		setTitle("MUI Component");
		setDefaultWindowPosition(WindowPosition.WINDOW);
		setVisible(true);
		createActions(tool);
		Msg.info(this, "MUI init complete!");
	}
	
	private void buildMainPanel() {
		mainPanel = new JPanel(new GridBagLayout());
		mainPanel.setMinimumSize(new Dimension(500,500));
		
		mainPanelConstraints = new GridBagConstraints();
		mainPanelConstraints.fill = GridBagConstraints.BOTH;
		mainPanelConstraints.gridwidth = GridBagConstraints.REMAINDER;
		mainPanelConstraints.weightx=0.9;
		mainPanelConstraints.weighty=0.9;
		
		inputPanel = new JPanel(new GridBagLayout());
        TitledBorder borderInp = BorderFactory.createTitledBorder("Manticore Options");
        borderInp.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        inputPanel.setBorder(borderInp);        
        inputPanelConstraints = new GridBagConstraints();
        inputPanelConstraints.fill = GridBagConstraints.BOTH;
        
        inputPanelConstraints.gridx=0;
        inputPanelConstraints.gridy=0;
        inputPanelConstraints.weightx=0.25;
        inputPanelConstraints.gridwidth=1;
        inputPanel.add(new JLabel("Program Path:"), inputPanelConstraints);
        
        programPathLbl = new JLabel(programPath);
        inputPanelConstraints.gridx=1;
        inputPanelConstraints.gridy=0;
        inputPanelConstraints.weightx=0.75;
        inputPanelConstraints.gridwidth=3;
        inputPanel.add(programPathLbl, inputPanelConstraints);
        
        JLabel commandArgsLbl = new JLabel("Command Args:");
        inputPanelConstraints.gridx=0;
        inputPanelConstraints.gridy=1;
        inputPanelConstraints.weightx=0.0;
        inputPanelConstraints.gridwidth=4;
        inputPanel.add(commandArgsLbl, inputPanelConstraints);

		commandArgsArea = new JTextArea();
		commandArgsArea.setToolTipText("Enter arguments as you would in CLI");
		commandArgsArea.setLineWrap(true);
		commandArgsArea.setWrapStyleWord(true);
		inputPanelConstraints.gridx=0;
        inputPanelConstraints.gridy=2;
        inputPanelConstraints.ipady=50;
        inputPanelConstraints.weightx=0.0;
        inputPanelConstraints.gridwidth=4;
        inputPanel.add(commandArgsArea, inputPanelConstraints);
        
        runBtn = new JButton("Run");
        runBtn.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				Msg.info(borderInp, "clicked run congrats"); 
				callManticore("lol");
			}
        	
        });
		inputPanelConstraints.gridx=0;
        inputPanelConstraints.gridy=3;
		inputPanelConstraints.weightx=0.9;
        inputPanelConstraints.ipady=0;
        inputPanelConstraints.gridwidth=4;
        inputPanelConstraints.insets = new Insets(10,0,0,0);
        inputPanel.add(runBtn, inputPanelConstraints);
        
        stopBtn = new JButton("Stop");
        stopBtn.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				Msg.info(borderInp, "clicked stop sadge");
			}
        	
        });
		inputPanelConstraints.gridx=0;
		inputPanelConstraints.gridy=4;
		inputPanelConstraints.weightx=0.9;
        inputPanelConstraints.gridwidth=4;
        inputPanelConstraints.anchor = GridBagConstraints.SOUTH;
        inputPanelConstraints.insets = new Insets(0,0,0,0);
        inputPanel.add(stopBtn, inputPanelConstraints);
        
		
        
		outputPanel = new JPanel(new GridBagLayout());
        TitledBorder borderOut = BorderFactory.createTitledBorder("Output");
        borderOut.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        outputPanel.setBorder(borderOut);        
        outputPanelConstraints = new GridBagConstraints();
        outputPanelConstraints.fill = GridBagConstraints.BOTH;
        
        outputPanelConstraints.gridx=0;
        outputPanelConstraints.gridy=0;
        outputPanelConstraints.weightx=1.0;
        
		outputArea = new JTextArea();
		outputArea.setEditable(false);
		outputArea.setLineWrap(true);
		outputArea.setWrapStyleWord(true);
        outputPanel.add(outputArea, outputPanelConstraints);

        mainPanel.add(inputPanel, mainPanelConstraints);
        mainPanel.add(outputPanel, mainPanelConstraints);
	}
	
	private void createActions(PluginTool tool){
		action = new DockingAction("MUI",getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Msg.info(this, "menu item test");
			}
		};
		action.setMenuBarData(new MenuData(new String[] {"MUI", "placeholder"}));

		tool.addAction(action);
	}
	
	protected void callManticore(String commandArgs) {
		// TODO: get nice input from manticore
		
		Msg.info(this, "in callmanticore");
		SwingWorker sw = new SwingWorker() {

			@Override
			protected Object doInBackground() throws Exception {
				ProcessBuilder pb = new ProcessBuilder("manticore", programPath);
           	 	try {
                    Process p = pb.start();
                    p.waitFor();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                    String line = "";
                    while ((line = reader.readLine()) != null){
                    	Msg.info(this, line); 
                    	logText.append(line);
                    }      
                    
                    reader.close();
                } catch (Exception e1) {
                    e1.printStackTrace();
                }           

				return null;
			}
			@Override
			protected void done() {
				Msg.info(this, "done executing");
            	outputArea.setText(logText.toString());

			}
		};

		sw.execute();
	}
	
    public void setProgram(Program p) {
        program = p;
        programPath = program.getExecutablePath();
        if(programPathLbl != null) { // if mainPanel built before program activated
            programPathLbl.setText(programPath);
        }
        Msg.info(this, "program set!!!");
        action.setEnabled(true);       
    }

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	
}
