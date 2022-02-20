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
import muicore.MUICore.ManticoreInstance;
import muicore.ManticoreUIGrpc;
import io.grpc.*;
import io.grpc.stub.StreamObserver;

import java.io.*;
import java.net.*;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;

/**
 * The class representing each instance of Manticore.
 */
public class ManticoreRunner {

	private ManticoreInstance manticoreInstance;

	public ManticoreRunner() {
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
			}

		};

		MUIPlugin.asyncMUICoreStub.start(cliArgs, startObserver);
	}

}
