# dashboard.py
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

class Dashboard:
    """
    Generates an interactive dashboard from session logs and detection report.
    """
    def __init__(self, log_file, detection_file):
        self.log_file = log_file
        self.detection_file = detection_file
        self.logs = []
        self.indicators = []

    def load_data(self):
        """
        Load session logs and detection indicators.
        """
        with open(self.log_file, 'r') as f:
            self.logs = json.load(f)

        with open(self.detection_file, 'r') as f:
            self.indicators = json.load(f)

    def generate_timeline(self, output_html='session_dashboard.html'):
        """
        Generate interactive timeline dashboard.
        """
        # Convert logs to DataFrame
        df_logs = pd.DataFrame(self.logs)
        df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'])

        # Commands executed timeline
        commands_df = df_logs[df_logs['event_type'] == 'command_sent']
        fig = px.timeline(commands_df, x_start='timestamp', x_end='timestamp',
                          y='component', text='details', title='Command Timeline')
        fig.update_yaxes(autorange="reversed")  # Server on top

        # Overlay bytes transferred as scatter
        fig.add_trace(go.Scatter(
            x=df_logs['timestamp'],
            y=[0.5]*len(df_logs),
            mode='markers',
            marker=dict(size=df_logs['bytes']/10, color='orange', opacity=0.6),
            name='Bytes Transferred'
        ))

        # Add detection indicators as annotations
        for ind in self.indicators:
            ts = pd.to_datetime(ind['timestamp'])
            fig.add_annotation(
                x=ts, y=1, text=f"{ind['indicator']} ({ind['severity']})",
                showarrow=True, arrowhead=2, ax=0, ay=-40, bgcolor='red', opacity=0.7
            )

        # Save to HTML
        fig.write_html(output_html)
        print(f"Dashboard saved: {output_html}")