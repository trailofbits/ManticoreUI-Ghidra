package mui;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import javax.swing.JButton;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
import javax.swing.tree.TreePath;

import ghidra.util.Msg;

import muicore.MUICore;
import muicore.MUICore.CLIArguments;
import muicore.MUICore.MUILogMessage;
import muicore.MUICore.MUIMessageList;
import muicore.MUICore.ManticoreInstance;
import muicore.MUICore.ManticoreRunningStatus;
import muicore.MUICore.TerminateResponse;
import muicore.ManticoreUIGrpc;
import io.grpc.*;
import io.grpc.stub.StreamObserver;

import java.io.*;
import java.net.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 * The class representing each instance of Manticore.
 */
public class ManticoreRunner {

	private ManticoreInstance manticoreInstance;
	private StringBuilder logText;

	private boolean hasStarted;
	private boolean isRunning;
	private boolean wasTerminated;

	public ManticoreRunner() {
		logText = new StringBuilder();
		hasStarted = false;
		isRunning = false;
		wasTerminated = false;
	}

	public void startManticore(CLIArguments cliArgs) {
		StreamObserver<ManticoreInstance> startObserver = new StreamObserver<ManticoreInstance>() {

			@Override
			public void onCompleted() {
			}

			@Override
			public void onError(Throwable arg0) {
			}

			@Override
			public void onNext(ManticoreInstance mcore) {
				manticoreInstance = mcore;
				hasStarted = true;
				isRunning = true;
			}

		};

		MUIPlugin.asyncMUICoreStub.start(cliArgs, startObserver);
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
		StreamObserver<MUIMessageList> messagelistObserver =
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

		MUIPlugin.asyncMUICoreStub.getMessageList(manticoreInstance, messagelistObserver);
	}

	public String getLogText() {
		return logText.toString();
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
		MUIPlugin.asyncMUICoreStub.checkManticoreRunning(manticoreInstance, null);
	}

	public boolean getIsRunning() {
		return isRunning;
	}

}
