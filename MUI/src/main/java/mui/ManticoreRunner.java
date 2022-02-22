package mui;

import muicore.MUICore.CLIArguments;
import muicore.MUICore.MUILogMessage;
import muicore.MUICore.MUIMessageList;
import muicore.MUICore.MUIState;
import muicore.MUICore.MUIStateList;
import muicore.MUICore.ManticoreInstance;
import muicore.MUICore.ManticoreRunningStatus;
import muicore.MUICore.TerminateResponse;

import io.grpc.stub.StreamObserver;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JTextArea;
import javax.swing.tree.TreePath;

import ghidra.util.Msg;

/**
 * The class representing each instance of Manticore.
 */
public class ManticoreRunner {

	private ManticoreInstance manticoreInstance;

	private boolean hasStarted;
	private boolean isRunning;
	private boolean wasTerminated;

	private JTextArea logText;
	private JButton stopBtn;

	private List<MUIState> activeStates;
	private List<MUIState> waitingStates;
	private List<MUIState> forkedStates;

	private List<MUIState> erroredStates;
	private List<MUIState> completeStates;

	public HashSet<TreePath> stateListExpandedPaths;

	public ManticoreRunner() {
		hasStarted = false;
		isRunning = false;
		wasTerminated = false;

		logText = new JTextArea();
		stopBtn = new JButton();

		activeStates = new ArrayList<MUIState>();
		waitingStates = new ArrayList<MUIState>();
		forkedStates = new ArrayList<MUIState>();
		erroredStates = new ArrayList<MUIState>();
		completeStates = new ArrayList<MUIState>();

		stateListExpandedPaths = new HashSet<TreePath>();
	}

	public void startManticore(CLIArguments cliArgs) {

		StreamObserver<ManticoreInstance> startObserver = new StreamObserver<ManticoreInstance>() {

			@Override
			public void onCompleted() {
				Msg.info(this, "COMPLETED");
				Msg.info(this, hasStarted);

			}

			@Override
			public void onError(Throwable arg0) {
			}

			@Override
			public void onNext(ManticoreInstance mcore) {
				Msg.info(this, "OK MCORE ONNEXT");
				setManticoreInstance(mcore);
				Msg.info(this, mcore.getUuid());
				setHasStarted(true);
				setIsRunning(true);

				Msg.info(this, hasStarted);
			}

		};

		Msg.info(this, "TRY ASYNC");

		MUIPlugin.asyncMUICoreStub.start(cliArgs, startObserver);
	}

	public void setManticoreInstance(ManticoreInstance m) {
		manticoreInstance = m;
	}

	public void setIsRunning(boolean b) {
		isRunning = true;
	}

	public void setHasStarted(boolean b) {
		hasStarted = true;
	}

	public boolean getHasStarted() {
		return hasStarted;
	}

	public void terminateManticore() {

		StreamObserver<TerminateResponse> terminateObserver =
			new StreamObserver<TerminateResponse>() {

				@Override
				public void onCompleted() {
				}

				@Override
				public void onError(Throwable arg0) {
				}

				@Override
				public void onNext(TerminateResponse resp) {
					wasTerminated = resp.getSuccess();
					isRunning = !resp.getSuccess();
				}

			};
		MUIPlugin.asyncMUICoreStub.terminate(manticoreInstance, terminateObserver);
	}

	public boolean getWasTerminated() {
		return wasTerminated;
	}

	public void fetchMessageLogs() {

		StreamObserver<MUIMessageList> messageListObserver =
			new StreamObserver<MUIMessageList>() {

				@Override
				public void onCompleted() {
				}

				@Override
				public void onError(Throwable arg0) {
				}

				@Override
				public void onNext(MUIMessageList messageList) {
					for (MUILogMessage msg : messageList.getMessagesList()) {
						logText.append(msg.getContent());
					}
				}
			};

		MUIPlugin.asyncMUICoreStub.getMessageList(manticoreInstance, messageListObserver);
	}

	public JTextArea getLogText() {
		return logText;
	}

	public JButton getStopBtn() {
		return stopBtn;
	}

	public void setLogUIElems(MUILogContentComponent content) {
		logText = content.logArea;
		stopBtn = content.stopButton;
	}

	public void fetchStateList() {

		StreamObserver<MUIStateList> stateListObserver = new StreamObserver<MUIStateList>() {

			@Override
			public void onCompleted() {
			}

			@Override
			public void onError(Throwable arg0) {
			}

			@Override
			public void onNext(MUIStateList muiStateList) {
				activeStates = muiStateList.getActiveStatesList();
				waitingStates = muiStateList.getWaitingStatesList();
				forkedStates = muiStateList.getForkedStatesList();
				erroredStates = muiStateList.getErroredStatesList();
				completeStates = muiStateList.getCompleteStatesList();

				if (MUIPlugin.stateList.runnerDisplayed == ManticoreRunner.this) { // tab could've change in between fetch and onNext
					MUIPlugin.stateList.updateShownStates(ManticoreRunner.this);
				}

			}

		};

		MUIPlugin.asyncMUICoreStub.getStateList(manticoreInstance, stateListObserver);
	}

	public List<MUIState> getActiveStates() {
		return activeStates;
	}

	public List<MUIState> getWaitingStates() {
		return waitingStates;
	}

	public List<MUIState> getForkedStates() {
		return forkedStates;
	}

	public List<MUIState> getErroredStates() {
		return erroredStates;
	}

	public List<MUIState> getCompleteStates() {
		return completeStates;
	}

	public void fetchIsRunning() {

		StreamObserver<ManticoreRunningStatus> runningObserver =
			new StreamObserver<ManticoreRunningStatus>() {

				@Override
				public void onCompleted() {
				}

				@Override
				public void onError(Throwable arg0) {
				}

				@Override
				public void onNext(ManticoreRunningStatus status) {
					isRunning = status.getIsRunning();
				}

			};
		MUIPlugin.asyncMUICoreStub.checkManticoreRunning(manticoreInstance, runningObserver);
	}

	public boolean getIsRunning() {
		return isRunning;
	}

}
