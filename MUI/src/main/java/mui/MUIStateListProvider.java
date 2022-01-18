package mui;

import java.awt.BorderLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;

import docking.WindowPosition;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

public class MUIStateListProvider extends ComponentProviderAdapter {

	private JPanel mainPanel;
	private JTree stateListTree;
	private JScrollPane stateListView;

	public DefaultMutableTreeNode activeNode;
	public DefaultMutableTreeNode waitingNode;
	public DefaultMutableTreeNode forkedNode;
	public DefaultMutableTreeNode completeNode;
	public DefaultMutableTreeNode erroredNode;

	public MUIStateListProvider(PluginTool tool, String name, String owner) {
		super(tool, name, owner);
		buildStateListView();
		buildMainPanel();
		setTitle("MUI State List");
		setDefaultWindowPosition(WindowPosition.RIGHT);
		setVisible(true);
	}

	private void buildMainPanel() {
		mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(stateListView);
	}

	private void buildStateListView() {
		DefaultMutableTreeNode rootNode =
			new DefaultMutableTreeNode("State List");

		activeNode = new DefaultMutableTreeNode("Active");
		waitingNode = new DefaultMutableTreeNode("Waiting");
		forkedNode = new DefaultMutableTreeNode("Forked");
		completeNode = new DefaultMutableTreeNode("Complete");
		erroredNode = new DefaultMutableTreeNode("Errored");

		rootNode.add(activeNode);
		rootNode.add(waitingNode);
		rootNode.add(forkedNode);
		rootNode.add(completeNode);
		rootNode.add(erroredNode);

		stateListTree = new JTree(rootNode);
		JScrollPane stateListView = new JScrollPane(stateListTree);

	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

}
