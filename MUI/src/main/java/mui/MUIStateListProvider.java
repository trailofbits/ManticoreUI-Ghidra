package mui;

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.HashMap;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import docking.WindowPosition;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import mserialize.StateOuterClass;

public class MUIStateListProvider extends ComponentProviderAdapter {

	private JPanel mainPanel;
	private static JTree stateListTree;
	private static DefaultTreeModel treeModel;
	private static JScrollPane stateListView;

	private static DefaultMutableTreeNode activeNode;
	private static DefaultMutableTreeNode waitingNode;
	private static DefaultMutableTreeNode completeNode;
	private static DefaultMutableTreeNode erroredNode;

	public static ManticoreRunner runnerDisplayed;

	public MUIStateListProvider(PluginTool tool, String name) {
		super(tool, name, name);
		buildStateListView();
		buildMainPanel();
		setTitle("MUI State List");
		setDefaultWindowPosition(WindowPosition.RIGHT);
		setVisible(false);
	}

	private void buildMainPanel() {
		mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(stateListView, BorderLayout.CENTER);
	}

	private void buildStateListView() {
		DefaultMutableTreeNode rootNode =
			new DefaultMutableTreeNode("State List");

		activeNode = new DefaultMutableTreeNode("Active");
		waitingNode = new DefaultMutableTreeNode("Waiting");
		completeNode = new DefaultMutableTreeNode("Complete");
		erroredNode = new DefaultMutableTreeNode("Errored");

		rootNode.add(activeNode);
		rootNode.add(waitingNode);
		rootNode.add(completeNode);
		rootNode.add(erroredNode);

		treeModel = new DefaultTreeModel(rootNode);

		stateListTree = new JTree(treeModel);
		stateListView = new JScrollPane(stateListTree);
	}

	public static void tryUpdate(ManticoreRunner runner, Boolean force) {

		if (force || runner == runnerDisplayed) {
			ManticoreStateListModel stateListModel = runner.stateListModel;
			activeNode.removeAllChildren();
			waitingNode.removeAllChildren();
			completeNode.removeAllChildren();
			erroredNode.removeAllChildren();
			try {
				stateListModel.stateList.get(StateOuterClass.State.StateType.BUSY)
						.forEach((st) -> activeNode.add(stateToNode(st)));
				stateListModel.stateList.get(StateOuterClass.State.StateType.READY)
						.forEach((st) -> waitingNode.add(stateToNode(st)));
				stateListModel.stateList.get(StateOuterClass.State.StateType.KILLED)
						.forEach((st) -> erroredNode.add(stateToNode(st)));
				stateListModel.stateList.get(StateOuterClass.State.StateType.TERMINATED)
						.forEach((st) -> completeNode.add(stateToNode(st)));
			}
			catch (NullPointerException npe) {
				Msg.info(stateListModel, "no states yet");
			}

			treeModel.reload();

			// expand top-level nodes
			int curRow = stateListTree.getRowCount() - 1;
			while (curRow-- >= 0) {
				stateListTree.expandRow(curRow);
			}
		}
	}

	private static DefaultMutableTreeNode stateToNode(StateOuterClass.State st) {
		return new DefaultMutableTreeNode(st.getId());
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

}
