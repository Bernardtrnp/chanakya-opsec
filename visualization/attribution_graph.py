"""
Network Graph Visualization for Multi-Layer Attribution Correlation

This tool creates interactive network graphs showing how OPSEC signals
correlate across different layers to create attribution.

Visualizes:
- Signal nodes (DNS, Metadata, Network, etc.)
- Correlation edges (weighted by strength)
- Attribution pathways (how signals combine)
- Risk scores (color-coded by severity)
"""

try:
    import networkx as nx
    import plotly.graph_objects as go
    import plotly.express as px
except ImportError:
    print("WARNING: NetworkX and/or Plotly not installed.")
    print("Install with: pip install networkx plotly")
    nx = None
    go = None


class AttributionGraphVisualizer:
    """Creates interactive network graphs for OPSEC attribution analysis"""
    
    def __init__(self):
        self.graph = nx.DiGraph() if nx else None
        self.signals = []
        self.correlations = []
    
    def add_signal(self, signal_id: str, layer: str, attribution_weight: float, 
                   description: str = ""):
        """
        Add a signal node to the graph
        
        Args:
            signal_id: Unique identifier for the signal
            layer: OPSEC layer (DNS, Metadata, Network, etc.)
            attribution_weight: Attribution weight (0.0-1.0)
            description: Human-readable description
        """
        if not self.graph:
            return
        
        self.graph.add_node(
            signal_id,
            layer=layer,
            attribution_weight=attribution_weight,
            description=description,
            risk_level=self._get_risk_level(attribution_weight)
        )
        
        self.signals.append({
            'id': signal_id,
            'layer': layer,
            'aw': attribution_weight,
            'description': description
        })
    
    def add_correlation(self, signal1: str, signal2: str, 
                       correlation_strength: float, description: str = ""):
        """
        Add a correlation edge between two signals
        
        Args:
            signal1: Source signal ID
            signal2: Target signal ID
            correlation_strength: Correlation strength (0.0-1.0)
            description: How the signals correlate
        """
        if not self.graph:
            return
        
        self.graph.add_edge(
            signal1,
            signal2,
            weight=correlation_strength,
            description=description
        )
        
        self.correlations.append({
            'from': signal1,
            'to': signal2,
            'strength': correlation_strength,
            'description': description
        })
    
    def visualize(self, title: str = "OPSEC Attribution Correlation Graph",
                  output_file: str = "attribution_graph.html"):
        """
        Create interactive Plotly visualization
        
        Args:
            title: Graph title
            output_file: Output HTML file path
        """
        if not self.graph or not go:
            print("ERROR: NetworkX or Plotly not available")
            return
        
        # Calculate layout
        pos = nx.spring_layout(self.graph, k=1, iterations=50)
        
        # Create edges
        edge_trace = []
        for edge in self.graph.edges(data=True):
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            weight = edge[2].get('weight', 0.5)
            
            edge_trace.append(
                go.Scatter(
                    x=[x0, x1, None],
                    y=[y0, y1, None],
                    mode='lines',
                    line=dict(
                        width=weight * 5,  # Thicker = stronger correlation
                        color=f'rgba(100, 100, 100, {weight})'
                    ),
                    hoverinfo='text',
                    text=edge[2].get('description', ''),
                    showlegend=False
                )
            )
        
        # Create nodes
        node_x = []
        node_y = []
        node_color = []
        node_text = []
        node_size = []
        
        for node in self.graph.nodes(data=True):
            node_id = node[0]
            node_data = node[1]
            
            x, y = pos[node_id]
            node_x.append(x)
            node_y.append(y)
            
            # Color by attribution weight (risk)
            aw = node_data.get('attribution_weight', 0)
            node_color.append(aw)
            
            # Size by importance
            node_size.append(20 + (aw * 30))
            
            # Hover text
            hover_text = f"<b>{node_id}</b><br>"
            hover_text += f"Layer: {node_data.get('layer', 'Unknown')}<br>"
            hover_text += f"Attribution Weight: {aw:.2f}<br>"
            hover_text += f"Risk: {node_data.get('risk_level', 'Unknown')}<br>"
            hover_text += f"{node_data.get('description', '')}"
            node_text.append(hover_text)
        
        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
            mode='markers+text',
            text=[self.graph.nodes[n].get('layer', '') for n in self.graph.nodes()],
            textposition="top center",
            hoverinfo='text',
            hovertext=node_text,
            marker=dict(
                size=node_size,
                color=node_color,
                colorscale='RdYlGn_r',  # Red (high risk) to Green (low risk)
                showscale=True,
                colorbar=dict(
                    title="Attribution<br>Weight",
                    thickness=15,
                    x=1.1
                ),
                line=dict(width=2, color='white')
            )
        )
        
        # Create figure
        fig = go.Figure(
            data=edge_trace + [node_trace],
            layout=go.Layout(
                title=title,
                titlefont=dict(size=20),
                showlegend=False,
                hovermode='closest',
                margin=dict(b=0, l=0, r=0, t=40),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                plot_bgcolor='rgba(240,240,240,1)',
                height=800
            )
        )
        
        # Save to file
        fig.write_html(output_file)
        print(f"✅ Visualization saved to: {output_file}")
        print(f"📊 Open in browser to view interactive graph")
        
        return fig
    
    def calculate_attribution_paths(self, target_node: str):
        """
        Calculate all attribution paths leading to a target node
        
        Args:
            target_node: The node to analyze paths to
            
        Returns:
            List of paths with combined attribution weights
        """
        if not self.graph or not nx:
            return []
        
        # Find all nodes that have paths to target
        paths = []
        for source in self.graph.nodes():
            if source == target_node:
                continue
            
            # Find all simple paths
            try:
                all_paths = list(nx.all_simple_paths(self.graph, source, target_node))
                for path in all_paths:
                    # Calculate combined attribution weight along path
                    combined_aw = 1.0
                    for i in range(len(path) - 1):
                        edge_weight = self.graph[path[i]][path[i+1]].get('weight', 0.5)
                        combined_aw *= edge_weight
                    
                    # Multiply by source node's attribution weight
                    source_aw = self.graph.nodes[source].get('attribution_weight', 0.5)
                    combined_aw *= source_aw
                    
                    paths.append({
                        'path': ' → '.join(path),
                        'attribution_weight': combined_aw,
                        'hops': len(path) - 1
                    })
            except nx.NetworkXNoPath:
                continue
        
        # Sort by attribution weight (highest first)
        paths.sort(key=lambda x: x['attribution_weight'], reverse=True)
        
        return paths
    
    def generate_report(self):
        """Generate text report of attribution analysis"""
        if not self.graph:
            return "ERROR: No graph data"
        
        report = []
        report.append("=" * 80)
        report.append("OPSEC ATTRIBUTION CORRELATION ANALYSIS")
        report.append("=" * 80)
        report.append("")
        
        # Summary statistics
        report.append(f"Total signals: {self.graph.number_of_nodes()}")
        report.append(f"Total correlations: {self.graph.number_of_edges()}")
        report.append("")
        
        # High-risk signals
        report.append("HIGH-RISK SIGNALS (AW > 0.70):")
        report.append("-" * 80)
        high_risk = [(n, data) for n, data in self.graph.nodes(data=True) 
                     if data.get('attribution_weight', 0) > 0.70]
        high_risk.sort(key=lambda x: x[1]['attribution_weight'], reverse=True)
        
        for node_id, data in high_risk:
            aw = data.get('attribution_weight', 0)
            layer = data.get('layer', 'Unknown')
            desc = data.get('description', '')
            report.append(f"  [{aw:.2f}] {node_id} ({layer})")
            if desc:
                report.append(f"       {desc}")
        
        report.append("")
        
        # Strongest correlations
        report.append("STRONGEST CORRELATIONS (Strength > 0.70):")
        report.append("-" * 80)
        strong_corr = [(e[0], e[1], e[2]) for e in self.graph.edges(data=True)
                       if e[2].get('weight', 0) > 0.70]
        strong_corr.sort(key=lambda x: x[2]['weight'], reverse=True)
        
        for src, dst, data in strong_corr:
            weight = data.get('weight', 0)
            desc = data.get('description', '')
            report.append(f"  [{weight:.2f}] {src} → {dst}")
            if desc:
                report.append(f"       {desc}")
        
        return "\n".join(report)
    
    # Helper methods
    
    def _get_risk_level(self, attribution_weight: float) -> str:
        """Convert attribution weight to risk level"""
        if attribution_weight >= 0.80:
            return "CRITICAL"
        elif attribution_weight >= 0.60:
            return "HIGH"
        elif attribution_weight >= 0.40:
            return "MEDIUM"
        elif attribution_weight >= 0.20:
            return "LOW"
        else:
            return "MINIMAL"


# Example usage
def create_example_graph():
    """Create example attribution graph"""
    viz = AttributionGraphVisualizer()
    
    # Add signals from different layers
    viz.add_signal('DNS_Leak', 'DNS', 0.85, 
                   'DNS queries leaked to ISP resolver outside VPN')
    viz.add_signal('Timezone_UTC-5', 'Metadata', 0.65,
                   'Timezone metadata in Git commits reveals location')
    viz.add_signal('Bitcoin_Address', 'Financial', 0.90,
                   'Bitcoin address linked to KYC exchange (Coinbase)')
    viz.add_signal('Timing_Pattern', 'Temporal', 0.70,
                   'Activity occurs 9am-5pm EST (work hours)')
    viz.add_signal('GitHub_Username', 'OSINT', 0.80,
                   'GitHub username matches forum pseudonym')
    viz.add_signal('IP_Address', 'Network', 0.95,
                   'Home IP address in server logs')
    
    # Add correlations
    viz.add_correlation('DNS_Leak', 'IP_Address', 0.90,
                       'DNS queries from same IP as other activity')
   viz.add_correlation('Timezone_UTC-5', 'Timing_Pattern', 0.85,
                       'Timezone in metadata matches activity timing')
    viz.add_correlation('GitHub_Username', 'Bitcoin_Address', 0.75,
                       'GitHub username found in Bitcoin forum posts')
    viz.add_correlation('Timing_Pattern', 'IP_Address', 0.80,
                       'IP activity matches work hour pattern')
    viz.add_correlation('Bitcoin_Address', 'IP_Address', 0.95,
                       'Coinbase KYC linked to IP address')
    
    # Generate visualization
    viz.visualize(
        title="Multi-Layer OPSEC Attribution Correlation Graph",
        output_file="docs/attribution_graph_example.html"
    )
    
    # Generate report
    print(viz.generate_report())
    print()
    
    # Calculate attribution paths to IP_Address (final attribution)
    print("ATTRIBUTION PATHS TO IDENTITY:")
    print("=" * 80)
    paths = viz.calculate_attribution_paths('IP_Address')
    for i, path in enumerate(paths[:5], 1):  # Top 5 paths
        print(f"{i}. {path['path']}")
        print(f"   Combined AW: {path['attribution_weight']:.3f} ({path['hops']} hops)")
        print()


if __name__ == '__main__':
    if nx and go:
        print("Creating example attribution correlation graph...")
        create_example_graph()
    else:
        print("Please install required packages:")
        print("  pip install networkx plotly")
