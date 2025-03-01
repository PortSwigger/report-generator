package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.io.File;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private List<Map<String, String>> vulnerabilities;
    private String pentesterName = "TEST";
    private String projectName = "TEST.COM";
    private JTextField pentesterField;
    private JTextField projectField;
    private JTable vulnTable;
    private VulnerabilityTableModel tableModel;
    
    private class VulnerabilityTableModel extends AbstractTableModel {
        private final String[] columnNames = {"Type", "Risk Level", "Description"};
        
        @Override
        public int getRowCount() {
            return vulnerabilities.size();
        }
        
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }
        
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Map<String, String> vuln = vulnerabilities.get(rowIndex);
            switch (columnIndex) {
                case 0: return vuln.get("type");
                case 1: return vuln.get("risk_level");
                case 2: return vuln.get("description").split("\n")[0]; // First line only
                default: return "";
            }
        }
    }
    
    private void showVulnerabilityDetails(int rowIndex) {
        Map<String, String> vuln = vulnerabilities.get(rowIndex);
        
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(mainPanel), 
                "Vulnerability Details", Dialog.ModalityType.APPLICATION_MODAL);
        
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Vulnerability type
        JLabel typeLabel = new JLabel("Type: " + vuln.get("type"));
        typeLabel.setFont(typeLabel.getFont().deriveFont(Font.BOLD));
        panel.add(typeLabel);
        panel.add(Box.createVerticalStrut(10));
        
        // Risk level
        JLabel riskLabel = new JLabel("Risk Level: " + vuln.get("risk_level"));
        riskLabel.setFont(riskLabel.getFont().deriveFont(Font.BOLD));
        panel.add(riskLabel);
        panel.add(Box.createVerticalStrut(10));
        
        // Description
        JLabel descLabel = new JLabel("Description:");
        descLabel.setFont(descLabel.getFont().deriveFont(Font.BOLD));
        panel.add(descLabel);
        
        JTextArea descArea = new JTextArea(vuln.get("description"));
        descArea.setEditable(false);
        descArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        JScrollPane descScroll = new JScrollPane(descArea);
        descScroll.setPreferredSize(new Dimension(600, 150));
        panel.add(descScroll);
        panel.add(Box.createVerticalStrut(10));
        
        // Impact
        JLabel impactLabel = new JLabel("Impact:");
        impactLabel.setFont(impactLabel.getFont().deriveFont(Font.BOLD));
        panel.add(impactLabel);
        
        JTextArea impactArea = new JTextArea(vuln.get("impact"));
        impactArea.setEditable(false);
        impactArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        impactArea.setLineWrap(true);
        impactArea.setWrapStyleWord(true);
        JScrollPane impactScroll = new JScrollPane(impactArea);
        impactScroll.setPreferredSize(new Dimension(600, 100));
        panel.add(impactScroll);
        panel.add(Box.createVerticalStrut(10));
        
        // Request evidence
        if (vuln.containsKey("request_highlight")) {
            JLabel requestLabel = new JLabel("Request Evidence:");
            requestLabel.setFont(requestLabel.getFont().deriveFont(Font.BOLD));
            panel.add(requestLabel);
            
            JTextArea requestArea = new JTextArea(vuln.get("request_highlight"));
            requestArea.setEditable(false);
            requestArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
            JScrollPane requestScroll = new JScrollPane(requestArea);
            requestScroll.setPreferredSize(new Dimension(600, 150));
            panel.add(requestScroll);
            panel.add(Box.createVerticalStrut(10));
        }
        
        // Response evidence
        if (vuln.containsKey("response_highlight")) {
            JLabel responseLabel = new JLabel("Response Evidence:");
            responseLabel.setFont(responseLabel.getFont().deriveFont(Font.BOLD));
            panel.add(responseLabel);
            
            JTextArea responseArea = new JTextArea(vuln.get("response_highlight"));
            responseArea.setEditable(false);
            responseArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
            JScrollPane responseScroll = new JScrollPane(responseArea);
            responseScroll.setPreferredSize(new Dimension(600, 150));
            panel.add(responseScroll);
            panel.add(Box.createVerticalStrut(10));
        }
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton editButton = new JButton("Edit");
        editButton.addActionListener(e -> {
            dialog.dispose();
            editVulnerability(rowIndex);
        });
        
        JButton deleteButton = new JButton("Delete");
        deleteButton.addActionListener(e -> {
            int choice = JOptionPane.showConfirmDialog(dialog,
                "Are you sure you want to delete this vulnerability?",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
            
            if (choice == JOptionPane.YES_OPTION) {
                vulnerabilities.remove(rowIndex);
                updateVulnerabilityList();
                dialog.dispose();
            }
        });
        
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(closeButton);
        panel.add(buttonPanel);
        
        dialog.add(panel);
        dialog.pack();
        dialog.setLocationRelativeTo(mainPanel);
        dialog.setVisible(true);
    }
    
    private void editVulnerability(int selectedRow) {
        Map<String, String> selectedVuln = vulnerabilities.get(selectedRow);
        
        // Create a new VulnerabilityDialog in edit mode
        VulnerabilityDialog dialog = new VulnerabilityDialog(
            mainPanel,
            null,  // No message needed for editing
            null,  // No invocation needed for editing
            callbacks,
            helpers,
            true   // Set to edit mode
        );
        
        // Pre-fill the dialog with existing values
        dialog.setValues(selectedVuln);
        
        // Show the dialog
        dialog.setVisible(true);
        
        // If user clicked Save Changes
        Map<String, String> result = dialog.getResult();
        if (result != null) {
            // Update the vulnerability in the list
            vulnerabilities.set(selectedRow, result);
            // Refresh the table
            ((AbstractTableModel) vulnTable.getModel()).fireTableRowsUpdated(selectedRow, selectedRow);
        }
    }
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.vulnerabilities = new ArrayList<>();

        // Extension adını ayarla
        callbacks.setExtensionName("Pentest Report Generator");

        // UI oluştur
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                mainPanel = new JPanel();
                mainPanel.setLayout(new BorderLayout());
                
                // Üst panel - Proje bilgileri
                JPanel topPanel = new JPanel(new GridLayout(3, 2, 5, 5));
                topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
                
                pentesterField = new JTextField(pentesterName);
                projectField = new JTextField(projectName);
                
                topPanel.add(new JLabel("Pentester Name:"));
                topPanel.add(pentesterField);
                topPanel.add(new JLabel("Project Name:"));
                topPanel.add(projectField);
                
                // Rapor oluşturma butonları
                JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
                
                JButton newReportButton = new JButton("New Report");
                newReportButton.addActionListener(e -> {
                    int choice = JOptionPane.showConfirmDialog(mainPanel,
                        "This will clear all current vulnerabilities. Are you sure?",
                        "New Report",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.WARNING_MESSAGE);
                    
                    if (choice == JOptionPane.YES_OPTION) {
                        vulnerabilities.clear();
                        updateVulnerabilityList();
                        pentesterField.setText("TEST");
                        projectField.setText("TEST.COM");
                    }
                });
                
                JButton pdfButton = new JButton("Save as PDF");
                JButton wordButton = new JButton("Save as Word");
                
                pdfButton.addActionListener(e -> generateReport("pdf"));
                wordButton.addActionListener(e -> generateReport("word"));
                
                buttonPanel.add(newReportButton);
                buttonPanel.add(pdfButton);
                buttonPanel.add(wordButton);
                topPanel.add(buttonPanel);
                
                mainPanel.add(topPanel, BorderLayout.NORTH);
                
                // Vulnerability listesi
                JPanel vulnListPanel = new JPanel(new BorderLayout());
                vulnListPanel.setBorder(BorderFactory.createTitledBorder("Vulnerabilities"));
                
                tableModel = new VulnerabilityTableModel();
                vulnTable = new JTable(tableModel);
                vulnTable.setFillsViewportHeight(true);
                
                // Add double click listener
                vulnTable.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        if (e.getClickCount() == 2) {
                            int row = vulnTable.rowAtPoint(e.getPoint());
                            if (row >= 0) {
                                showVulnerabilityDetails(row);
                            }
                        }
                    }
                });
                
                // Risk Level sütununa renk ekle
                vulnTable.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value,
                            boolean isSelected, boolean hasFocus, int row, int column) {
                        Component c = super.getTableCellRendererComponent(table, value,
                                isSelected, hasFocus, row, column);
                        
                        if (!isSelected) {
                            String risk = (String) value;
                            switch (risk) {
                                case "Critical":
                                    c.setBackground(new Color(255, 0, 0, 50));
                                    break;
                                case "High":
                                    c.setBackground(new Color(255, 165, 0, 50));
                                    break;
                                case "Medium":
                                    c.setBackground(new Color(255, 255, 0, 50));
                                    break;
                                case "Low":
                                    c.setBackground(new Color(0, 255, 0, 50));
                                    break;
                                default:
                                    c.setBackground(new Color(200, 200, 200, 50));
                                    break;
                            }
                        }
                        
                        return c;
                    }
                });
                
                JScrollPane scrollPane = new JScrollPane(vulnTable);
                vulnListPanel.add(scrollPane, BorderLayout.CENTER);
                
                mainPanel.add(vulnListPanel, BorderLayout.CENTER);
                
                // Tab'e ekle
                callbacks.customizeUiComponent(mainPanel);
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });

        // Context menu factory'i kaydet
        callbacks.registerContextMenuFactory(this);
        
        callbacks.printOutput("Pentest Report Generator has been successfully added!");
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
            invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
            
            JMenuItem menuItem = new JMenuItem("Add to Pentest Report");
            menuItem.addActionListener(e -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) {
                    showVulnerabilityDialog(messages[0], invocation);
                }
            });
            menuItems.add(menuItem);
        }
        
        return menuItems;
    }
    
    private void showVulnerabilityDialog(IHttpRequestResponse message, IContextMenuInvocation invocation) {
        SwingUtilities.invokeLater(() -> {
            VulnerabilityDialog dialog = new VulnerabilityDialog(mainPanel, message, invocation, callbacks, helpers);
            dialog.setVisible(true);
            
            Map<String, String> result = dialog.getResult();
            if (result != null) {
                vulnerabilities.add(result);
                updateVulnerabilityList();
            }
        });
    }
    
    private void updateVulnerabilityList() {
        tableModel.fireTableDataChanged();
    }
    
    private void generateReport(String type) {
        // Proje bilgilerini güncelle
        pentesterName = pentesterField.getText().trim();
        if (pentesterName.isEmpty()) pentesterName = "TEST";
        
        projectName = projectField.getText().trim();
        if (projectName.isEmpty()) projectName = "TEST.COM";
        
        if (type.equals("pdf")) {
            generatePDFReport();
        } else {
            generateWordReport();
        }
    }
    
    private void generatePDFReport() {
        BurpReportGenerator.generatePDFReport(pentesterName, projectName, vulnerabilities, callbacks);
    }
    
    private void generateWordReport() {
        BurpReportGenerator.generateWordReport(pentesterName, projectName, vulnerabilities, callbacks);
    }
    
    @Override
    public String getTabCaption() {
        return "Pentest Report";
    }
    
    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
} 