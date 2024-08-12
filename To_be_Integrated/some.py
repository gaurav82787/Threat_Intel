from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.clock import Clock
import psutil
import os

class ProcessMonitorApp(App):
    def build(self):
        self.process_to_kill = None
        self.ignore_list = []
        self.history = []
        self.counter = 0
        self.layout = BoxLayout(orientation='vertical')
        self.info_label = Label(text='Monitoring CPU usage...', size_hint=(1, 0.8))
        self.layout.add_widget(self.info_label)
        
        self.quit_button = Button(text='Quit', size_hint=(1, 0.2))
        self.quit_button.bind(on_press=self.stop)
        self.layout.add_widget(self.quit_button)
        
        Clock.schedule_interval(self.check_processes, 5)  # Check every 5 seconds
        return self.layout

    def check_processes(self, *args):
        high_cpu_processes = []
        if self.counter >= 120:
            self.counter = 0
            self.history.clear()
        else:
            self.counter += 1
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                cpu_usage = proc.info['cpu_percent']
                if cpu_usage > 40:
                    high_cpu_processes.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if high_cpu_processes:
            self.process_to_kill = high_cpu_processes[0]  # Just take the first high CPU process
            if self.process_to_kill.info["pid"] not in self.ignore_list and self.process_to_kill.info["pid"] not in self.history:
                self.history.append(self.process_to_kill.info["pid"])
                self.show_kill_popup(self.process_to_kill)

    def show_kill_popup(self, proc):
        if self.process_to_kill is None:
            return

        content = BoxLayout(orientation='vertical')
        content.add_widget(Label(text=f'Process "{proc.info["name"]}" (PID: {proc.info["pid"]}) is consuming {proc.info["cpu_percent"]}% CPU.'))
        
        btn_kill = Button(text='Kill Process')
        btn_kill.bind(on_press=self.kill_process)
        content.add_widget(btn_kill)
        
        btn_ignore = Button(text='Ignore')
        btn_ignore.bind(on_press=self.ignore_process)
        content.add_widget(btn_ignore)
        
        self.popup = Popup(title='High CPU Usage Warning', content=content, size_hint=(0.8, 0.4))
        self.popup.open()

    def kill_process(self, instance):
        if self.process_to_kill is not None:
            os.system(f'kill {self.process_to_kill.info["pid"]}')
            try:
                #self.process_to_kill.terminate()
                #self.process_to_kill.wait(timeout=3)  # Wait for the process to terminate
                self.info_label.text = f'Killed process "{self.process_to_kill.info["name"]}" (PID: {self.process_to_kill.info["pid"]}).'
            except:
                self.info_label.text = f'Process "{self.process_to_kill.info["name"]}" (PID: {self.process_to_kill.info["pid"]}) not found.'
            #except psutil.AccessDenied:
             #   self.info_label.text = f'Access denied to kill process "{self.process_to_kill.info["name"]}" (PID: {self.process_to_kill.info["pid"]}).'
            self.process_to_kill = None
            self.popup.dismiss()
        else:
            self.popup.dismiss()

    def ignore_process(self, instance):
        self.ignore_list.append(self.process_to_kill.info["pid"])
        self.process_to_kill = None
        self.popup.dismiss()

if __name__ == '__main__':
    ProcessMonitorApp().run()

