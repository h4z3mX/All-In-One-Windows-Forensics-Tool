import winreg

def collect_scheduled_tasks():
    """Collect scheduled tasks' names from the registry."""
    try:
        # Registry keys for scheduled tasks
        tasks_base_key = r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"
        scheduled_tasks = []

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, tasks_base_key) as tasks_key:
            i = 0
            while True:
                try:
                    # Get the GUID of each task
                    guid = winreg.EnumKey(tasks_key, i)
                    i += 1

                    # Access the details of the task using the GUID
                    task_key_path = f"{tasks_base_key}\\{guid}"
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, task_key_path) as task_details_key:
                        # Fetch the `Path` value (name of the task)
                        path, _ = winreg.QueryValueEx(task_details_key, "Path")
                        scheduled_tasks.append(f"Task Name: {path}")
                except OSError:  # No more tasks
                    break

        # Return the collected tasks
        return scheduled_tasks

    except PermissionError:  # Catch Access Denied errors
        raise Exception("Access Denied. Please run the script as Administrator.")
    except FileNotFoundError:
        raise Exception("Scheduled Tasks registry key not found.")
    except Exception as e:
        raise Exception(f"Error collecting scheduled tasks: {e}")
