import platform

def detect_os() -> str:
	name = platform.system().lower()
	if name.startswith("win"):
		return "Windows"
	if name == "darwin":
		return "macOS"
	return "Linux"
