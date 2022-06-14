package mui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.ArrayList;
import java.util.HashMap;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import ghidra.program.model.address.Address;
import ghidra.util.Msg;

import muicore.MUICore.Hook;
import muicore.MUICore.Hook.Builder;
import muicore.MUICore.Hook.HookType;

public class MUIHookListComponent extends JPanel {

	private JTree hookListTree;
	private JScrollPane hookListView;
	private DefaultTreeModel treeModel;

	private DefaultMutableTreeNode rootNode;
	private DefaultMutableTreeNode findNode;
	private DefaultMutableTreeNode avoidNode;
	private DefaultMutableTreeNode customNode;
	private DefaultMutableTreeNode globalNode;

	private HashMap<String, DefaultMutableTreeNode> hookLocations;

	public MUIHookListComponent() {
		setLayout(new BorderLayout());
		hookLocations = new HashMap<>();
		buildHookListView();
		add(hookListView, BorderLayout.CENTER);
		setSize(new Dimension(900, 200));
		setMaximumSize(new Dimension(900, 300));
		setSize(new Dimension(900, 200));
		setMaximumSize(new Dimension(900, 300));

	}

	private void buildHookListView() {
		rootNode = new DefaultMutableTreeNode("Hooks");
		findNode = new DefaultMutableTreeNode("Find");
		avoidNode = new DefaultMutableTreeNode("Avoid");
		customNode = new DefaultMutableTreeNode("Custom");
		globalNode = new DefaultMutableTreeNode("Global");

		rootNode.add(findNode);
		rootNode.add(avoidNode);
		rootNode.add(customNode);
		rootNode.add(globalNode);

		treeModel = new DefaultTreeModel(rootNode);

		hookListTree = new JTree(treeModel);
		hookListTree.setMinimumSize(new Dimension(0, 0));
		hookListTree.setPreferredSize(new Dimension(900, 100));
		hookListView = new JScrollPane(hookListTree);
		hookListView.setMinimumSize(new Dimension(0, 0));
		hookListTree.setPreferredSize(new Dimension(900, 100));

	}

	public void addHook(MUIHookUserObject hook) {
		DefaultMutableTreeNode node = new DefaultMutableTreeNode(hook);
		switch (hook.type) {
			case FIND:
				findNode.add(node);
				break;
			case AVOID:
				avoidNode.add(node);
				break;
			case CUSTOM:
				customNode.add(node);
				break;
			case GLOBAL:
				globalNode.add(node);
				break;
			default:
				break;
		}

		hookLocations.put(hook.name.toString() + hook.type.name(), node);

		// TODO: Show hook counts?

		treeModel.reload();
		expandTree();

	}

	public boolean removeHookIfExists(String name, HookType type) {
		DefaultMutableTreeNode target = hookLocations.get(name + type.name());

		if (target == null) {
			return false;
		}

		target.removeFromParent();
		treeModel.reload();
		expandTree();
		return true;
	}

	public void clearHooks() {

		findNode.removeAllChildren();
		avoidNode.removeAllChildren();

		treeModel.reload();

	}

	public ArrayList<Hook> getAllMUIHooks() {
		ArrayList<Hook> hooks = new ArrayList<>();

		for (int i = 0; i < findNode.getChildCount(); i++) {
			hooks.add(nodeToMUIHook((DefaultMutableTreeNode) findNode.getChildAt(i)));
		}
		for (int i = 0; i < avoidNode.getChildCount(); i++) {
			hooks.add(nodeToMUIHook((DefaultMutableTreeNode) avoidNode.getChildAt(i)));
		}
		for (int i = 0; i < customNode.getChildCount(); i++) {
			hooks.add(nodeToMUIHook((DefaultMutableTreeNode) customNode.getChildAt(i)));
		}
		for (int i = 0; i < globalNode.getChildCount(); i++) {
			hooks.add(nodeToMUIHook((DefaultMutableTreeNode) globalNode.getChildAt(i)));
		}

		return hooks;
	}

	private void expandTree() {
		int row = 1;
		while (row++ < hookListTree.getRowCount()) {
			hookListTree.expandRow(row);
		}
	}

	private Hook nodeToMUIHook(DefaultMutableTreeNode node) {
		MUIHookUserObject hook = (MUIHookUserObject) node.getUserObject();
		Builder b = Hook.newBuilder().setType(hook.type);
		switch (hook.type) {
			case FIND:
			case AVOID:
				b.setAddress(
					Long.parseLong(hook.name, 16));
				break;
			case CUSTOM:
				b.setAddress(
					Long.parseLong(hook.name, 16));
			case GLOBAL:
				b.setFuncText(node.getUserObject().toString());
				break;
			default:
				break;
		}
		return b.build();
	}
}
