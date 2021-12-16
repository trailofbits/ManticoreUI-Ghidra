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

public class MUILogProvider extends ComponentProviderAdapter {
	
	private JPanel logPanel;
	
	private JScrollPane logScrollPane;
	private JTextArea logArea;
	
	private JToolBar logToolBar;
	private JButton stopButton;
	private JButton clearButton;
	
	private StringBuffer logStringBuf;
	
	private MUIProvider mainProvider;

	
	public MUILogProvider(PluginTool tool, String name) {
		super(tool, name, name);
		buildLogPanel();
		setTitle("MUI Log");
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setVisible(true);
		Msg.info(this, "created muilog");
	}
	
	public void setMainProvider(MUIProvider provider) {
		mainProvider = provider;
	}
	
	private void buildLogPanel() {
		logPanel = new JPanel();
		logPanel.setLayout(new BorderLayout());
		logPanel.setMinimumSize(new Dimension(300,300));	
		
		logArea = new JTextArea();
		logArea.setEditable(false);
		logArea.setLineWrap(true);
		logArea.setWrapStyleWord(true);
		logScrollPane = new JScrollPane(logArea, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		
		logPanel.add(logScrollPane, BorderLayout.CENTER);
		
		logToolBar = new JToolBar();
		logToolBar.setFloatable(false);
		stopButton = new JButton();
		stopButton.setIcon(ResourceManager.loadImage("images/stopNode.png"));
		stopButton.setEnabled(false);
		stopButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				mainProvider.stopManticore();
			}
			
		});
		
		clearButton = new JButton();
		clearButton.setIcon(ResourceManager.loadImage("images/erase16.png"));
		
		logToolBar.add(Box.createGlue()); // shifts buttons to the right
		logToolBar.add(stopButton);
		logToolBar.add(clearButton);
		
		logPanel.add(logToolBar, BorderLayout.PAGE_START);
		
		logStringBuf = new StringBuffer();
	}

	public void clearLog() {
		logArea.setText("");
		logStringBuf.setLength(0);
	}
	
	public void appendLog(String s) {
		Msg.info(this, s);
		logStringBuf.append(System.lineSeparator());
		logStringBuf.append(s);
		logArea.setText(logStringBuf.toString());
	}
	
	public void updateButtonStatus(Boolean isManticoreRunning) {
		stopButton.setEnabled(isManticoreRunning);
		clearButton.setEnabled(!isManticoreRunning);
	}
	
	@Override
	public JComponent getComponent() {
		return logPanel;
	}

}