package mui;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import javax.swing.JButton;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;

import ghidra.util.Msg;
import mserialize.StateOuterClass;

import java.io.*;
import java.net.*;
import java.time.Instant;
import java.util.List;

public class ManticoreRunner {

	private Boolean isTerminated;
	private Boolean isFinished;
	private JTextArea logArea;
	private JButton stopButton;

	private String host;
	private int port;

	public ManticoreRunner(JTextArea logArea, JButton stopButton) {
		isTerminated = false;
		isFinished = false;
		this.logArea = logArea;
		this.stopButton = stopButton;

		host = "localhost";
		port = 3214;
	}

	public void stopProc() {
		isTerminated = true;
	}

	public void callProc(String[] command) {

		stopButton.setEnabled(true);
		logArea.append(
			"Command: " + String.join(" ", command) + System.lineSeparator() +
				System.lineSeparator());

		SwingWorker sw =
			new SwingWorker() {
				Boolean errored = false;

				@Override
				protected Object doInBackground() throws Exception {
					ProcessBuilder pb = new ProcessBuilder(command);
					try {
						Process p = pb.start();
						BufferedReader reader =
							new BufferedReader(new InputStreamReader(p.getInputStream()));
						String line = "";
						fetchStates();
						while ((line = reader.readLine()) != null && !isTerminated) {
							logArea.append(line);
							logArea.append(System.lineSeparator());
						}
						if (isTerminated) {
							p.destroy();
						}
						else {							
							p.waitFor();
							final int exitValue = p.waitFor();
							if (exitValue != 0) {
								errored = true;
								try (final BufferedReader b =
									new BufferedReader(new InputStreamReader(p.getErrorStream()))) {
									String eline;
									if ((eline = b.readLine()) != null) {
										logArea.append(eline);
									}
								}
								catch (final IOException e) {
									e.printStackTrace();
								}
							}
						}
						reader.close();

					}
					catch (Exception e1) {
						errored = true;
						logArea.append(e1.getMessage());
						e1.printStackTrace();
					}
					return null;
				}

				@Override
				protected void done() {
					isFinished = true;
					if (isTerminated) {
						logArea.append("Manticore stopped by user.");
					}
					else if (errored) {
						logArea.append("Error! See stack trace above.");
					}
					else {
						logArea.append("Manticore execution complete.");
					}
					stopButton.setEnabled(false);
				}
			};
		sw.execute();
	}

	public void fetchStates() {
		while (!isFinished) {
			try {
				Socket stateSock = new Socket(host, port);
				InputStream stateInputStream = stateSock.getInputStream();
				try {
					List<StateOuterClass.State> stateList =
						StateOuterClass.StateList.parseFrom(stateInputStream).getStatesList();
					if (stateList.size() > 0) {
						ManticoreStateListModel newModel = new ManticoreStateListModel();
						for (StateOuterClass.State s : stateList) {
							newModel.stateList.get(s.getType()).add(s);
						}
						// update ui
					}
				}
				catch (Exception e) {
					Msg.info(this, e.toString());
				}
				stateSock.close();
			}
			catch (IOException se) {
				Msg.info(this, se.toString());
			}
			try {
				Thread.sleep(1000);
				;
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
	}
}
