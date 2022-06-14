package mui;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import muicore.MUICore.Hook.HookType;

public class MUIHookUserObject {
	public HookType type;
	public String name;
	public String func_text;

	public MUIHookUserObject(HookType type, String name, String func_text) {
		this.type = type;
		this.name = (name != null) ? name
				: "Global " + ZonedDateTime.now(ZoneId.systemDefault())
						.format(DateTimeFormatter.ofPattern("HH:mm:ss"));
		this.func_text = func_text;
	}

	@Override
	public String toString() {
		return name;
	}
}
