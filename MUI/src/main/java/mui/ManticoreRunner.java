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

	public ManticoreStateListModel stateListModel;

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

	public void callProc(String[] command, int portUsed) {

		stopButton.setEnabled(true);
		logArea.append(
			"Command: " + String.join(" ", command) + System.lineSeparator() +
				System.lineSeparator());

		port = portUsed;

		SwingWorker sw =
			new SwingWorker() {
				Boolean errored = false;

				@Override
				protected Object doInBackground() throws Exception {
					ProcessBuilder pb = new ProcessBuilder(command);
					try {
						Msg.info(this, "called doInBackground");
						Process p = pb.start();
						BufferedReader reader =
							new BufferedReader(new InputStreamReader(p.getInputStream()));
						String line = "";
						long prevtime = Instant.now().getEpochSecond();

						while ((line = reader.readLine()) != null && !isTerminated) {
							logArea.append(line);
							logArea.append(System.lineSeparator());
							if (Instant.now().getEpochSecond() - 2 > prevtime) { // >1s between updates
								Msg.info(this, "attempting fetchstate");
								prevtime = Instant.now().getEpochSecond();
								try {
									Socket stateSock = new Socket(host, port + 1); // port + 1 to get state server
									InputStream stateInputStream = stateSock.getInputStream();
									try {
										byte[] curBytes = stateInputStream.readAllBytes();
										StateOuterClass.StateList sl =
											StateOuterClass.StateList.parseFrom(curBytes);
										List<StateOuterClass.State> states =
											sl.getStatesList();
										if (states.size() > 0) {
											ManticoreStateListModel newModel =
												new ManticoreStateListModel();
											for (StateOuterClass.State s : states) {
												newModel.stateList.get(s.getType()).add(s);
											}
											stateListModel = newModel;
											Msg.info(this,
												Integer.toString(stateListModel.stateList.size()));
											updateStateList();
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
							}
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

	private void updateStateList() {
		MUIStateListProvider.tryUpdate(this, false);
	}

}
