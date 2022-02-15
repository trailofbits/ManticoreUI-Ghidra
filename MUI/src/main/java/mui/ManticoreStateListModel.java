package mui;

import java.util.*;

import muicore.MUICore;

public class ManticoreStateListModel {
	public HashMap<MUICore.State.StateType, ArrayList<MUICore.State>> stateList;

	public ManticoreStateListModel() {
		stateList = new HashMap();
		stateList.put(MUICore.State.StateType.READY,
			new ArrayList<MUICore.State>());
		stateList.put(MUICore.State.StateType.BUSY, new ArrayList<MUICore.State>());
		stateList.put(MUICore.State.StateType.KILLED,
			new ArrayList<MUICore.State>());
		stateList.put(MUICore.State.StateType.TERMINATED,
			new ArrayList<MUICore.State>());
		stateList.put(MUICore.State.StateType.UNRECOGNIZED,
			new ArrayList<MUICore.State>());
	}
}
