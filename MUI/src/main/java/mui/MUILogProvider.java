package mui;

import javax.swing.*;

import java.awt.*;
import java.awt.event.*;

import docking.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import resources.ResourceManager;

public class MUILogProvider extends ComponentProviderAdapter {

	private JPanel logPanel;

	private JScrollPane logScrollPane;
	private JTextArea logArea;

	private JToolBar logToolBar;
	private JButton stopButton;
	private JButton clearButton;

	private StringBuffer logStringBuf;

	private MUISetupProvider mainProvider;

	public MUILogProvider(PluginTool tool, String name) {
		super(tool, name, name);
		buildLogPanel();
		setTitle("MUI Log");
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setVisible(true);
	}

	public void setMainProvider(MUISetupProvider provider) {
		mainProvider = provider;
	}

	private void buildLogPanel() {
		logPanel = new JPanel();
		logPanel.setLayout(new BorderLayout());
		logPanel.setMinimumSize(new Dimension(300, 300));

		logArea = new JTextArea();
		logArea.setEditable(false);
		logArea.setLineWrap(true);
		logArea.setWrapStyleWord(true);
		logScrollPane = new JScrollPane(logArea, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

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
		clearButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				clearLog();
			}

		});
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