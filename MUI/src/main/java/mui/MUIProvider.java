package mui;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import java.awt.*;
import java.awt.event.*;

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
	
	private String manticoreCommand;
	
	private JPanel outputPanel;
	private GridBagConstraints outputPanelConstraints;
	
	
	public MUIProvider(PluginTool tool, String name, Program p) {
		super(tool, name, name);
		buildMainPanel();
		setIcon(ResourceManager.loadImage("images/erase16.png"));
		setTitle("MUI Component");
		setDefaultWindowPosition(WindowPosition.RIGHT);
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
			}
        	
        });
		inputPanelConstraints.gridx=0;
        inputPanelConstraints.gridy=3;
        inputPanelConstraints.ipady=0;
        inputPanelConstraints.weightx=1.0;
        inputPanelConstraints.gridwidth=2;
        inputPanelConstraints.anchor = GridBagConstraints.PAGE_END;
        inputPanelConstraints.insets = new Insets(10,0,0,0);
        inputPanel.add(runBtn, inputPanelConstraints);
        
        stopBtn = new JButton("Stop");
        stopBtn.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				Msg.info(borderInp, "clicked stop sadge");
			}
        	
        });
		inputPanelConstraints.gridx=2;
		inputPanelConstraints.gridy=3;
        inputPanelConstraints.weightx=1.0;
        inputPanelConstraints.gridwidth=2;
        inputPanelConstraints.anchor = GridBagConstraints.PAGE_END;
        inputPanelConstraints.insets = new Insets(10,0,0,0);
        inputPanel.add(stopBtn, inputPanelConstraints);


		mainPanel.add(inputPanel, mainPanelConstraints);
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
