import paramiko
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from tkinter import simpledialog
import os
import threading

class SFTPClient:
    def __init__(self, master):
        self.master = master
        self.master.title("SFTP Client")
        self.master.geometry("600x500")
        self.master.configure(bg="#f0f0f0")

        # Connection Frame
        self.connection_frame = tk.Frame(master, bg="#f0f0f0")
        self.connection_frame.pack(pady=10)

        self._create_connection_widgets()

        # Operations Frame
        self.operations_frame = tk.Frame(master, bg="#f0f0f0")
        self.operations_frame.pack(pady=10)

        tk.Button(self.operations_frame, text="Choose Action", command=self.choose_action).grid(row=0, column=0)

        # Output Area
        self.output_area = scrolledtext.ScrolledText(master, width=70, height=15)
        self.output_area.pack(pady=10)

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(master, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _create_connection_widgets(self):
        """Create widgets for connection frame."""
        tk.Label(self.connection_frame, text="Hostname:", bg="#f0f0f0").grid(row=0, column=0)
        self.hostname_entry = tk.Entry(self.connection_frame)
        self.hostname_entry.grid(row=0, column=1)

        tk.Label(self.connection_frame, text="Username:", bg="#f0f0f0").grid(row=1, column=0)
        self.username_entry = tk.Entry(self.connection_frame)
        self.username_entry.grid(row=1, column=1)

        tk.Label(self.connection_frame, text="Password:", bg="#f0f0f0").grid(row=2, column=0)
        self.password_entry = tk.Entry(self.connection_frame, show='*')
        self.password_entry.grid(row=2, column=1)

        tk.Button(self.connection_frame, text="Connect", command=self.connect).grid(row=3, columnspan=2)

    def connect(self):
        """Establish an SFTP connection."""
        hostname = self.hostname_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        try:
            # Initialize SSH Client
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(hostname, username=username, password=password)

            # Open SFTP session
            self.sftp_client = self.ssh_client.open_sftp()
            messagebox.showinfo("Connection", "Connected successfully!")
            self.output_area.insert(tk.END, "Connected to SFTP server.\n")
            self.status_var.set("Connected to SFTP server.")

            # Change to the desired FTP shared directory (modify this path as needed)
            self.shared_directory = '/ftp/'  # Set this to your shared folder's path
            self.sftp_client.chdir(self.shared_directory)  # Change to the shared directory
            
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self.status_var.set("Connection failed.")

    def choose_action(self):
        """Prompt user to choose between upload and download."""
        
        action = simpledialog.askstring("Choose Action", "Type 'upload' to upload or 'download' to download:")
        
        if action is None:
            return  # User canceled
        
        action = action.lower()
        
        if action == 'upload':
            self.upload_choice()
        elif action == 'download':
            self.download_choice()
        else:
            messagebox.showwarning("Invalid Input", "Please enter 'upload' or 'download'.")

    def upload_choice(self):
        """Prompt user to choose whether to upload a file or directory."""
        
        choice = simpledialog.askstring("Upload Choice", "Type 'file' to upload a file or 'directory' to upload a directory:")
        
        if choice is None:
            return
        
        choice = choice.lower()
        
        if choice == 'file':
            local_file_path = filedialog.askopenfilename()  # Allow user to select a file
            
            if not local_file_path:
                messagebox.showwarning("Upload", "No file selected for upload.")
                return
            
            threading.Thread(target=self.upload_file_threaded,
                             args=(local_file_path,)).start()

        elif choice == 'directory':
            local_directory_path = filedialog.askdirectory()  # Allow user to select a directory
            
            if not local_directory_path:
                messagebox.showwarning("Upload", "No directory selected for upload.")
                return
            
            threading.Thread(target=self.upload_directory_threaded,
                             args=(local_directory_path,)).start()

    def upload_file_threaded(self, local_file_path):
        """Threaded method for uploading a file."""
        
        try:
            remote_file_path = os.path.join(self.shared_directory, os.path.basename(local_file_path))
            print(f"Uploading: {local_file_path} to {remote_file_path}")
            self.sftp_client.put(local_file_path, remote_file_path)  # Upload file
            messagebox.showinfo("Upload", "File uploaded successfully!")
        
        except Exception as e:
            messagebox.showerror("Upload Error", str(e))

    def upload_directory_threaded(self, local_directory_path):
        """Threaded method for uploading a directory."""
        
        try:
            # Upload files recursively
            self.upload_directory(local_directory_path)
            messagebox.showinfo("Upload", "Directory uploaded successfully!")
        
        except Exception as e:
            messagebox.showerror("Upload Error", str(e))

    def upload_directory(self, local_path):
        """Recursively upload a directory."""
        
        for root, dirs, files in os.walk(local_path):
            relative_path = os.path.relpath(root, local_path)
            current_remote_path = os.path.join(self.shared_directory, relative_path)

            try:
                print(f"Creating remote directory: {current_remote_path}")
                try:
                    self.sftp_client.mkdir(current_remote_path)  # Create remote directory if it doesn't exist
                except IOError:
                    print(f"Remote directory already exists: {current_remote_path}")
                
                for file in files:
                    local_file_path = os.path.join(root, file)
                    remote_file_path = os.path.join(current_remote_path, file)

                    try:
                        print(f"Uploading: {local_file_path} to {remote_file_path}")
                        self.sftp_client.put(local_file_path, remote_file_path)  # Upload file
                    except Exception as e:
                        print(f"Failed to upload {local_file_path} - {str(e)}")

            except Exception as e:
                print(f"Error processing {current_remote_path} - {str(e)}")

    def download_choice(self):
        """Prompt user to choose whether to download a file or directory."""
        
        choice = simpledialog.askstring("Download Choice", "Type 'file' to download a file or 'directory' to download a directory:")
         
        if choice is None:
             return
        
        choice = choice.lower()
         
        if choice == 'file':
             selected_item = simpledialog.askstring("Select File", 
                                                     "Enter the name of the file to download:\n" + "\n".join(self.list_remote_files()))
             
             if selected_item and selected_item in self.list_remote_files():
                 local_directory = filedialog.askdirectory()  # Ask where to save locally

                 if not local_directory:
                     messagebox.showwarning("Download", "No local directory specified.")
                     return

                 threading.Thread(target=self.download_file_threaded,
                                  args=(selected_item, local_directory)).start()

        elif choice == 'directory':
             selected_item = simpledialog.askstring("Select Directory",
                                                     "Enter the name of the directory to download:\n" + "\n".join(self.list_remote_files()))
             
             if selected_item and selected_item in self.list_remote_files():
                 local_directory = filedialog.askdirectory()  # Ask where to save locally

                 if not local_directory:
                     messagebox.showwarning("Download", "No local directory specified.")
                     return

                 threading.Thread(target=self.download_directory_threaded,
                                  args=(selected_item, local_directory)).start()

    def download_file_threaded(self, selected_item, local_directory):
        
         """Threaded method for downloading a file."""
         
         try:
             local_file_path = os.path.join(local_directory ,selected_item)
             print(f"Downloading: {selected_item} to {local_file_path}")
             self.sftp_client.get(selected_item ,local_file_path)  # Download file
             messagebox.showinfo("Download","File downloaded successfully!")
         
         except Exception as e:
             messagebox.showerror("Download Error", str(e))

    def download_directory_threaded(self ,selected_item ,local_directory):
        
         """Threaded method for downloading a directory."""
         
         try:
             print(f"Downloading directory: {selected_item} to {local_directory}")
             items=self.sftp_client.listdir(selected_item)  # List items in the remote directory

             for item in items:
                 remote_item_path=os.path.join(selected_item,item)  # Full path of the item on the server
                
                 try:
                     attrs=self.sftp_client.stat(remote_item_path)  # Get attributes of the item
                    
                     if attrs.st_mode & 0o40000:  # Check if it's a directory
                         new_local_dir=os.path.join(local_directory,item)
                         os.makedirs(new_local_dir ,exist_ok=True)  # Create local directory if it doesn't exist
                         print(f"Created local directory: {new_local_dir}")
                         threading.Thread(target=self.download_directory_threaded,
                                          args=(remote_item_path,new_local_dir)).start()  # Recursively download subdirectory
                    
                     else:  # It's a file
                         local_file=os.path.join(local_directory,item)
                         print(f"Downloading: {remote_item_path} to {local_file}")
                         threading.Thread(target=self.download_file_threaded,
                                          args=(remote_item_path ,local_file)).start()  # Download file

                 except Exception as e:
                     print(f"Failed to download {remote_item_path} - {str(e)}")

         except Exception as e:
             messagebox.showerror("Download Error", str(e))

    def list_remote_files(self):
        
         """List files on the SFTP server and return them."""
         
         try:
             return self.sftp_client.listdir()  # List files in current directory on server
        
         except Exception as e:
             messagebox.showerror("Listing Error", str(e))
             return []

    def list_files(self):
        
         """Display files in the output area."""
         
         if not hasattr(self,'sftp_client'):
             messagebox.showwarning("List Files","Not connected to any SFTP server.")
             return
            
         try:
             file_list=self.list_remote_files()
             
             output_text="Files in current directory:\n"
             
             for file in file_list:
                 output_text+=f"{file}\n"
             
             self.output_area.insert(tk.END ,output_text)
             self.status_var.set("Listed files successfully.")
         
         except Exception as e:
             messagebox.showerror("Listing Error",str(e))
             self.status_var.set("Listing failed.")

    def clear_list(self):
        
         """Clear the output area."""
         
         self.output_area.delete(1.0 ,tk.END)  # Clear all text in the output area
         self.status_var.set("Output cleared.")

    def close_connection(self):
        
         """Close the SFTP connection."""
         
         if hasattr(self,'sftp_client'):
             try:
                 self.sftp_client.close()
                 if hasattr(self,'ssh_client'):
                     self.ssh_client.close()
                 messagebox.showinfo("Connection Closed","SFTP connection closed.")
                 print("SFTP connection closed.")  # Debugging output
            
             except Exception as e:
                 print(f"Error closing connection: {e}")  # Debugging output

if __name__ == "__main__":
    root=tk.Tk()
    sftp_client_app=SFTPClient(root)
    root.protocol("WM_DELETE_WINDOW",sftp_client_app.close_connection)  # Close connection on exit
    root.mainloop()
