package burp;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;
import org.apache.poi.xwpf.usermodel.*;
import org.apache.poi.util.Units;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PiePlot;
import org.jfree.data.general.DefaultPieDataset;

import javax.swing.*;
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.io.IOException;
import java.io.FileInputStream;

public class BurpReportGenerator {
    private static final Font TITLE_FONT = new Font(Font.FontFamily.HELVETICA, 24, Font.BOLD);
    private static final Font SUBTITLE_FONT = new Font(Font.FontFamily.HELVETICA, 18, Font.BOLD);
    private static final Font HEADING_FONT = new Font(Font.FontFamily.HELVETICA, 16, Font.BOLD);
    private static final Font NORMAL_FONT = new Font(Font.FontFamily.HELVETICA, 12, Font.NORMAL);
    
    private static final BaseColor CRITICAL_COLOR = new BaseColor(255, 89, 94);
    private static final BaseColor HIGH_COLOR = new BaseColor(255, 145, 77);
    private static final BaseColor MEDIUM_COLOR = new BaseColor(255, 202, 58);
    private static final BaseColor LOW_COLOR = new BaseColor(138, 201, 38);
    private static final BaseColor INFO_COLOR = new BaseColor(25, 130, 196);
    
    public static void generatePDFReport(String pentesterName, String projectName, 
            List<Map<String, String>> vulnerabilities, IBurpExtenderCallbacks callbacks) {
        try {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setSelectedFile(new File("pentest_report.pdf"));
            if (fileChooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) {
                return;
            }
            
            com.itextpdf.text.Document document = new com.itextpdf.text.Document(PageSize.A4, 50, 50, 50, 50);
            PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(fileChooser.getSelectedFile()));
            document.open();
            
            // Kapak sayfası
            addCoverPage(document, projectName, pentesterName);
            document.newPage();
            
            // İçindekiler
            addTableOfContents(document, vulnerabilities);
            document.newPage();
            
            // Executive Summary ve Grafikler
            addExecutiveSummary(document, vulnerabilities);
            document.newPage();
            
            // Detaylı bulgular
            addDetailedFindings(document, vulnerabilities);
            
            // Vulnerability Charts
            addVulnerabilityCharts(document, vulnerabilities);
            
            document.close();
            callbacks.printOutput("PDF report generated successfully!");
            
        } catch (Exception e) {
            callbacks.printError("Error generating PDF report: " + e.getMessage());
        }
    }
    
    private static void addCoverPage(com.itextpdf.text.Document document, String projectName, String pentesterName) throws DocumentException {
        // Sayfanın tam ortasına yerleştirmek için boşluk bırak
        float pageHeight = document.getPageSize().getHeight();
        float contentHeight = 250; // Tahmini içerik yüksekliği
        float topMargin = (pageHeight - contentHeight) / 2;
        
        // Üst boşluk
        Paragraph spacer = new Paragraph();
        spacer.setSpacingBefore(topMargin);
        document.add(spacer);
        
        // Proje başlığı
        Paragraph title = new Paragraph(projectName, TITLE_FONT);
        title.setAlignment(Element.ALIGN_CENTER);
        title.setSpacingAfter(30);
        document.add(title);
        
        // Alt başlık
        Paragraph subtitle = new Paragraph("Web Application Security Assessment", SUBTITLE_FONT);
        subtitle.setAlignment(Element.ALIGN_CENTER);
        subtitle.setSpacingAfter(100);
        document.add(subtitle);
        
        // Pentester ve tarih bilgileri
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");
        
        Paragraph preparedBy = new Paragraph();
        preparedBy.setAlignment(Element.ALIGN_CENTER);
        preparedBy.add(new Chunk("Prepared by: ", NORMAL_FONT));
        preparedBy.add(new Chunk(pentesterName, HEADING_FONT));
        document.add(preparedBy);
        
        Paragraph date = new Paragraph();
        date.setAlignment(Element.ALIGN_CENTER);
        date.setSpacingBefore(10);
        date.add(new Chunk("Date: " + dateFormat.format(new Date()), NORMAL_FONT));
        document.add(date);
    }
    
    private static void addExecutiveSummary(com.itextpdf.text.Document document, List<Map<String, String>> vulnerabilities) throws DocumentException {
        // Başlık
        Paragraph title = new Paragraph("Executive Summary", HEADING_FONT);
        title.setAlignment(Element.ALIGN_CENTER);
        title.setSpacingAfter(30);
        document.add(title);
        
        // Risk dağılımı
        Map<String, Integer> riskCounts = new HashMap<>();
        for (Map<String, String> vuln : vulnerabilities) {
            String risk = vuln.get("risk_level");
            riskCounts.put(risk, riskCounts.getOrDefault(risk, 0) + 1);
        }
        
        // Risk özet tablosu
        PdfPTable summaryTable = new PdfPTable(new float[]{2, 1});
        summaryTable.setWidthPercentage(80);
        summaryTable.setSpacingBefore(20);
        summaryTable.setHorizontalAlignment(Element.ALIGN_CENTER);
        
        // Başlık satırı
        PdfPCell typeHeader = new PdfPCell(new Phrase("Risk Level", HEADING_FONT));
        PdfPCell countHeader = new PdfPCell(new Phrase("Count", HEADING_FONT));
        typeHeader.setBackgroundColor(new BaseColor(240, 240, 240));
        countHeader.setBackgroundColor(new BaseColor(240, 240, 240));
        typeHeader.setPadding(5);
        countHeader.setPadding(5);
        summaryTable.addCell(typeHeader);
        summaryTable.addCell(countHeader);
        
        // Risk seviyeleri
        String[] riskLevels = {"Critical", "High", "Medium", "Low", "Informational"};
        for (String risk : riskLevels) {
            PdfPCell riskCell = new PdfPCell(new Phrase(risk, NORMAL_FONT));
            PdfPCell countCell = new PdfPCell(new Phrase(String.valueOf(riskCounts.getOrDefault(risk, 0)), NORMAL_FONT));
            
            // Risk seviyesine göre renklendirme
            BaseColor color = getColorForRiskLevel(risk);
            riskCell.setBackgroundColor(new BaseColor(color.getRGB()));
            countCell.setBackgroundColor(new BaseColor(color.getRGB()));
            
            riskCell.setPadding(5);
            countCell.setPadding(5);
            summaryTable.addCell(riskCell);
            summaryTable.addCell(countCell);
        }
        
        document.add(summaryTable);
    }
    
    private static void addDetailedFindings(com.itextpdf.text.Document document, List<Map<String, String>> vulnerabilities) throws DocumentException {
        // Başlık
        Paragraph title = new Paragraph("Detailed Findings", HEADING_FONT);
        title.setAlignment(Element.ALIGN_CENTER);
        title.setSpacingAfter(30);
        document.add(title);
        
        for (int i = 0; i < vulnerabilities.size(); i++) {
            Map<String, String> vuln = vulnerabilities.get(i);
            
            // Vulnerability başlığı
            PdfPTable vulnTable = new PdfPTable(1);
            vulnTable.setWidthPercentage(100);
            
            // Başlık hücresi
            PdfPCell titleCell = new PdfPCell();
            titleCell.setPadding(10);
            titleCell.setBackgroundColor(getColorForRiskLevel(vuln.get("risk_level")));
            
            Paragraph vulnTitle = new Paragraph();
            vulnTitle.add(new Chunk((i + 1) + ". " + vuln.get("type"), HEADING_FONT));
            vulnTitle.add(Chunk.NEWLINE);
            vulnTitle.add(new Chunk("Risk Level: " + vuln.get("risk_level"), NORMAL_FONT));
            
            titleCell.addElement(vulnTitle);
            vulnTable.addCell(titleCell);
            
            // İçerik hücreleri
            addContentCell(vulnTable, "Description", vuln.get("description"));
            addContentCell(vulnTable, "Impact", vuln.get("impact"));
            
            // Remediation Plan
            if (vuln.containsKey("remediation_plan")) {
                addContentCell(vulnTable, "Remediation Plan", vuln.get("remediation_plan"));
            }
            
            if (vuln.containsKey("request_highlight")) {
                addContentCell(vulnTable, "Request Evidence", vuln.get("request_highlight"));
            }
            if (vuln.containsKey("response_highlight")) {
                addContentCell(vulnTable, "Response Evidence", vuln.get("response_highlight"));
            }
            
            // Evidence Image
            if (vuln.containsKey("evidence_image")) {
                addContentCell(vulnTable, "Evidence Image", vuln.get("evidence_image"));
            }
            
            document.add(vulnTable);
            document.add(Chunk.NEWLINE);
        }
    }
    
    private static void addContentCell(PdfPTable table, String title, String content) {
        if (content == null || content.trim().isEmpty()) {
            return;
        }
        
        PdfPCell cell = new PdfPCell();
        cell.setPadding(10);
        
        if (title.equals("Evidence Image")) {
            try {
                // Resim dosyasını kontrol et
                File imageFile = new File(content);
                if (!imageFile.exists()) {
                    Paragraph errorP = new Paragraph();
                    errorP.add(new Chunk(title + ":\n", HEADING_FONT));
                    errorP.add(new Chunk("Image file not found: " + content, NORMAL_FONT));
                    cell.addElement(errorP);
                    table.addCell(cell);
                    return;
                }

                // Başlık ekle
                Paragraph titleP = new Paragraph();
                titleP.add(new Chunk(title + ":\n", HEADING_FONT));
                titleP.add(Chunk.NEWLINE);
                cell.addElement(titleP);

                // Resmi yükle
                Image img = Image.getInstance(content);
                
                // Resmi ölçeklendir
                img.scaleToFit(400f, 300f);
                
                // Resmi ortala
                img.setAlignment(Element.ALIGN_CENTER);
                
                // Resmi hücreye ekle
                cell.addElement(img);
                
                // Alt boşluk ekle
                Paragraph spacer = new Paragraph();
                spacer.add(Chunk.NEWLINE);
                cell.addElement(spacer);
                
            } catch (Exception e) {
                Paragraph errorP = new Paragraph();
                errorP.add(new Chunk(title + ":\n", HEADING_FONT));
                errorP.add(new Chunk("Error loading image: " + e.getMessage(), NORMAL_FONT));
                cell.addElement(errorP);
            }
        } else {
            Paragraph p = new Paragraph();
            p.add(new Chunk(title + ":\n", HEADING_FONT));
            p.add(Chunk.NEWLINE);
            p.add(new Chunk(content, NORMAL_FONT));
            cell.addElement(p);
        }
        
        table.addCell(cell);
    }
    
    private static void addTableOfContents(com.itextpdf.text.Document document, List<Map<String, String>> vulnerabilities) throws DocumentException {
        // Başlık
        Paragraph tocTitle = new Paragraph("Table of Contents", HEADING_FONT);
        tocTitle.setAlignment(Element.ALIGN_CENTER);
        tocTitle.setSpacingAfter(20);
        document.add(tocTitle);

        // İçindekiler tablosu için ana tablo
        PdfPTable mainTable = new PdfPTable(1);
        mainTable.setWidthPercentage(90);
        mainTable.setSpacingBefore(10);
        mainTable.setSpacingAfter(10);

        // İçindekiler için iç tablo
        PdfPTable tocTable = new PdfPTable(2);
        tocTable.setWidthPercentage(100);
        float[] columnWidths = {85f, 15f};
        tocTable.setWidths(columnWidths);

        // Ana bölümler için özel font ve stil
        Font sectionFont = new Font(Font.FontFamily.HELVETICA, 12, Font.BOLD);
        Font subSectionFont = new Font(Font.FontFamily.HELVETICA, 11, Font.NORMAL);
        BaseColor lightGray = new BaseColor(245, 245, 245);

        // 1. Executive Summary
        PdfPCell mainSection1 = new PdfPCell(new Phrase("1. Executive Summary", sectionFont));
        PdfPCell pageNum1 = new PdfPCell(new Phrase("3", sectionFont));
        styleTableCell(mainSection1, lightGray, true);
        styleTableCell(pageNum1, lightGray, true);
        tocTable.addCell(mainSection1);
        tocTable.addCell(pageNum1);

        // 2. Detailed Findings
        PdfPCell mainSection2 = new PdfPCell(new Phrase("2. Detailed Findings", sectionFont));
        PdfPCell pageNum2 = new PdfPCell(new Phrase("4", sectionFont));
        styleTableCell(mainSection2, lightGray, true);
        styleTableCell(pageNum2, lightGray, true);
        tocTable.addCell(mainSection2);
        tocTable.addCell(pageNum2);

        // 2.x Vulnerability entries
        for (int i = 0; i < vulnerabilities.size(); i++) {
            Map<String, String> vuln = vulnerabilities.get(i);
            PdfPCell subSection = new PdfPCell(new Phrase("    2." + (i + 1) + ". " + vuln.get("type"), subSectionFont));
            PdfPCell subPageNum = new PdfPCell(new Phrase(String.valueOf(4 + i), subSectionFont));
            styleTableCell(subSection, null, false);
            styleTableCell(subPageNum, null, false);
            tocTable.addCell(subSection);
            tocTable.addCell(subPageNum);
        }

        // 3. Vulnerability Statistics
        PdfPCell mainSection3 = new PdfPCell(new Phrase("3. Vulnerability Statistics", sectionFont));
        PdfPCell pageNum3 = new PdfPCell(new Phrase(String.valueOf(5 + vulnerabilities.size()), sectionFont));
        styleTableCell(mainSection3, lightGray, true);
        styleTableCell(pageNum3, lightGray, true);
        tocTable.addCell(mainSection3);
        tocTable.addCell(pageNum3);

        // Ana tabloya iç tabloyu ekle
        PdfPCell tocCell = new PdfPCell(tocTable);
        tocCell.setPadding(10);
        tocCell.setBorder(Rectangle.BOX);
        mainTable.addCell(tocCell);

        document.add(mainTable);
    }
    
    private static void styleTableCell(PdfPCell cell, BaseColor backgroundColor, boolean isMainSection) {
        cell.setBorder(Rectangle.NO_BORDER);
        cell.setPaddingTop(5);
        cell.setPaddingBottom(5);
        cell.setPaddingLeft(isMainSection ? 5 : 20);
        cell.setPaddingRight(5);
        if (backgroundColor != null) {
            cell.setBackgroundColor(backgroundColor);
        }
        if (!isMainSection) {
            cell.setBorderWidthBottom(0.1f);
            cell.setBorderColorBottom(BaseColor.LIGHT_GRAY);
        }
    }
    
    private static void addVulnerabilityCharts(com.itextpdf.text.Document document, List<Map<String, String>> vulnerabilities) throws DocumentException {
        try {
            document.newPage();
            
            // Başlık
            Paragraph title = new Paragraph("Vulnerability Statistics", HEADING_FONT);
            title.setAlignment(Element.ALIGN_CENTER);
            title.setSpacingAfter(30);
            document.add(title);
            
            // Risk seviyesi dağılımı
            Map<String, Integer> riskCounts = new HashMap<>();
            for (Map<String, String> vuln : vulnerabilities) {
                String risk = vuln.get("risk_level");
                riskCounts.put(risk, riskCounts.getOrDefault(risk, 0) + 1);
            }
            
            // Pasta grafik için veri hazırlama
            DefaultPieDataset dataset = new DefaultPieDataset();
            for (Map.Entry<String, Integer> entry : riskCounts.entrySet()) {
                dataset.setValue(entry.getKey(), entry.getValue());
            }
            
            // Pasta grafik oluşturma
            JFreeChart chart = ChartFactory.createPieChart(
                "Risk Level Distribution",
                dataset,
                true,
                true,
                false
            );
            
            // Grafik görünümünü özelleştirme
            PiePlot plot = (PiePlot) chart.getPlot();
            plot.setSectionPaint("Critical", new Color(CRITICAL_COLOR.getRGB()));
            plot.setSectionPaint("High", new Color(HIGH_COLOR.getRGB()));
            plot.setSectionPaint("Medium", new Color(MEDIUM_COLOR.getRGB()));
            plot.setSectionPaint("Low", new Color(LOW_COLOR.getRGB()));
            plot.setSectionPaint("Informational", new Color(INFO_COLOR.getRGB()));
            
            // Grafiği PDF'e ekleme
            BufferedImage chartImage = chart.createBufferedImage(500, 300);
            Image image = Image.getInstance(chartImage, null);
            image.setAlignment(Element.ALIGN_CENTER);
            document.add(image);
        } catch (IOException e) {
            throw new DocumentException("Error creating vulnerability chart: " + e.getMessage());
        }
    }
    
    private static BaseColor getColorForRiskLevel(String risk) {
        switch (risk) {
            case "Critical": return CRITICAL_COLOR;
            case "High": return HIGH_COLOR;
            case "Medium": return MEDIUM_COLOR;
            case "Low": return LOW_COLOR;
            default: return INFO_COLOR;
        }
    }
    
    public static void generateWordReport(String pentesterName, String projectName, 
            List<Map<String, String>> vulnerabilities, IBurpExtenderCallbacks callbacks) {
        try {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setSelectedFile(new File("pentest_report.docx"));
            if (fileChooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) {
                return;
            }
            
            XWPFDocument document = new XWPFDocument();
            
            // Kapak sayfası
            XWPFParagraph title = document.createParagraph();
            title.setAlignment(ParagraphAlignment.CENTER);
            XWPFRun titleRun = title.createRun();
            titleRun.setText(projectName);
            titleRun.setFontSize(24);
            titleRun.setBold(true);
            titleRun.setFontFamily("Helvetica");
            titleRun.addBreak();
            titleRun.addBreak();
            
            XWPFParagraph subtitle = document.createParagraph();
            subtitle.setAlignment(ParagraphAlignment.CENTER);
            XWPFRun subtitleRun = subtitle.createRun();
            subtitleRun.setText("Web Application Security Assessment");
            subtitleRun.setFontSize(18);
            subtitleRun.setBold(true);
            subtitleRun.setFontFamily("Helvetica");
            subtitleRun.addBreak();
            subtitleRun.addBreak();
            
            // Pentester ve tarih
            SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");
            XWPFParagraph info = document.createParagraph();
            info.setAlignment(ParagraphAlignment.CENTER);
            XWPFRun infoRun = info.createRun();
            infoRun.setText("Prepared by: " + pentesterName);
            infoRun.setFontSize(12);
            infoRun.setFontFamily("Helvetica");
            infoRun.addBreak();
            
            XWPFRun dateRun = info.createRun();
            dateRun.setText("Date: " + dateFormat.format(new Date()));
            dateRun.setFontSize(12);
            dateRun.setFontFamily("Helvetica");
            
            document.createParagraph().createRun().addBreak(BreakType.PAGE);
            
            // İçindekiler
            XWPFParagraph tocTitle = document.createParagraph();
            tocTitle.setAlignment(ParagraphAlignment.CENTER);
            XWPFRun tocTitleRun = tocTitle.createRun();
            tocTitleRun.setText("Table of Contents");
            tocTitleRun.setFontSize(16);
            tocTitleRun.setBold(true);
            tocTitleRun.setFontFamily("Helvetica");
            tocTitleRun.addBreak();
            
            // İçindekiler tablosu
            XWPFTable tocTable = document.createTable(1, 2);
            tocTable.setWidth("90%");
            
            // Tablo stilini ayarla
            tocTable.setTopBorder(XWPFTable.XWPFBorderType.SINGLE, 12, 0, "E5E5E5");
            tocTable.setBottomBorder(XWPFTable.XWPFBorderType.SINGLE, 12, 0, "E5E5E5");
            tocTable.setLeftBorder(XWPFTable.XWPFBorderType.SINGLE, 12, 0, "E5E5E5");
            tocTable.setRightBorder(XWPFTable.XWPFBorderType.SINGLE, 12, 0, "E5E5E5");
            
            // Ana bölümler
            addTocEntry(document, tocTable, "1. Executive Summary", "3", true);
            addTocEntry(document, tocTable, "2. Detailed Findings", "4", true);
            
            // Alt bölümler (zaafiyetler)
            for (int i = 0; i < vulnerabilities.size(); i++) {
                Map<String, String> vuln = vulnerabilities.get(i);
                addTocEntry(document, tocTable, "    2." + (i + 1) + ". " + vuln.get("type"), 
                           String.valueOf(4 + i), false);
            }
            
            addTocEntry(document, tocTable, "3. Vulnerability Statistics", 
                       String.valueOf(5 + vulnerabilities.size()), true);
            
            document.createParagraph().createRun().addBreak(BreakType.PAGE);
            
            // Executive Summary
            XWPFParagraph summaryTitle = document.createParagraph();
            summaryTitle.setAlignment(ParagraphAlignment.CENTER);
            XWPFRun summaryTitleRun = summaryTitle.createRun();
            summaryTitleRun.setText("Executive Summary");
            summaryTitleRun.setFontSize(16);
            summaryTitleRun.setBold(true);
            summaryTitleRun.setFontFamily("Helvetica");
            summaryTitleRun.addBreak();
            
            // Risk özet tablosu
            XWPFTable summaryTable = document.createTable();
            summaryTable.setWidth("80%");
            
            // Tablo başlıkları
            XWPFTableRow headerRow = summaryTable.getRow(0);
            setTableCell(headerRow.getCell(0), "Risk Level", true);
            setTableCell(headerRow.addNewTableCell(), "Count", true);
            
            // Risk seviyeleri ve sayıları
            Map<String, Integer> riskCounts = new HashMap<>();
            for (Map<String, String> vuln : vulnerabilities) {
                String risk = vuln.get("risk_level");
                riskCounts.put(risk, riskCounts.getOrDefault(risk, 0) + 1);
            }
            
            String[] riskLevels = {"Critical", "High", "Medium", "Low", "Informational"};
            for (String risk : riskLevels) {
                XWPFTableRow row = summaryTable.createRow();
                setTableCell(row.getCell(0), risk, false);
                setTableCell(row.getCell(1), String.valueOf(riskCounts.getOrDefault(risk, 0)), false);
            }
            
            document.createParagraph().createRun().addBreak(BreakType.PAGE);
            
            // Detaylı bulgular
            XWPFParagraph findingsTitle = document.createParagraph();
            findingsTitle.setAlignment(ParagraphAlignment.CENTER);
            XWPFRun findingsTitleRun = findingsTitle.createRun();
            findingsTitleRun.setText("Detailed Findings");
            findingsTitleRun.setFontSize(16);
            findingsTitleRun.setBold(true);
            findingsTitleRun.setFontFamily("Helvetica");
            findingsTitleRun.addBreak();
            
            for (int i = 0; i < vulnerabilities.size(); i++) {
                Map<String, String> vuln = vulnerabilities.get(i);
                
                // Zafiyet başlığı ve tablosu
                XWPFTable vulnTable = document.createTable();
                vulnTable.setWidth("100%");
                
                // Başlık satırı
                XWPFTableRow titleRow = vulnTable.getRow(0);
                XWPFTableCell titleCell = titleRow.getCell(0);
                titleCell.setColor(getRiskLevelColor(vuln.get("risk_level")));
                
                XWPFParagraph vulnTitle = titleCell.getParagraphs().get(0);
                XWPFRun vulnTitleRun = vulnTitle.createRun();
                vulnTitleRun.setText((i + 1) + ". " + vuln.get("type"));
                vulnTitleRun.setFontSize(14);
                vulnTitleRun.setBold(true);
                vulnTitleRun.setFontFamily("Helvetica");
                vulnTitleRun.addBreak();
                
                XWPFRun riskRun = vulnTitle.createRun();
                riskRun.setText("Risk Level: " + vuln.get("risk_level"));
                riskRun.setFontSize(12);
                riskRun.setFontFamily("Helvetica");
                
                // İçerik bölümleri
                addVulnSection(vulnTable, "Description", vuln.get("description"));
                addVulnSection(vulnTable, "Impact", vuln.get("impact"));
                
                if (vuln.containsKey("remediation_plan")) {
                    addVulnSection(vulnTable, "Remediation Plan", vuln.get("remediation_plan"));
                }
                
                if (vuln.containsKey("request_highlight")) {
                    addVulnSection(vulnTable, "Request Evidence", vuln.get("request_highlight"));
                }
                if (vuln.containsKey("response_highlight")) {
                    addVulnSection(vulnTable, "Response Evidence", vuln.get("response_highlight"));
                }
                
                // Evidence Image
                if (vuln.containsKey("evidence_image")) {
                    addVulnSection(vulnTable, "Evidence Image", vuln.get("evidence_image"));
                }
                
                document.createParagraph().createRun().addBreak();
            }
            
            FileOutputStream out = new FileOutputStream(fileChooser.getSelectedFile());
            document.write(out);
            out.close();
            document.close();
            
            callbacks.printOutput("Word report generated successfully!");
            
        } catch (Exception e) {
            callbacks.printError("Error generating Word report: " + e.getMessage());
        }
    }
    
    private static void addTocEntry(XWPFDocument doc, XWPFTable table, String text, String pageNum, boolean isMainSection) {
        XWPFTableRow row = table.createRow();
        XWPFTableCell textCell = row.getCell(0);
        XWPFTableCell pageCell = row.getCell(1);
        
        // Ana bölüm ise arka plan rengini ayarla
        if (isMainSection) {
            textCell.setColor("F5F5F5");
            pageCell.setColor("F5F5F5");
        }
        
        XWPFParagraph p1 = textCell.getParagraphs().get(0);
        XWPFRun r1 = p1.createRun();
        r1.setText(text);
        r1.setBold(isMainSection);
        r1.setFontFamily("Helvetica");
        r1.setFontSize(isMainSection ? 12 : 11);
        
        if (!isMainSection) {
            p1.setIndentationLeft(500); // Alt bölümler için girinti
        }
        
        XWPFParagraph p2 = pageCell.getParagraphs().get(0);
        XWPFRun r2 = p2.createRun();
        r2.setText(pageNum);
        r2.setBold(isMainSection);
        r2.setFontFamily("Helvetica");
        r2.setFontSize(isMainSection ? 12 : 11);
    }
    
    private static void setTableCell(XWPFTableCell cell, String text, boolean isHeader) {
        XWPFParagraph p = cell.getParagraphs().get(0);
        XWPFRun r = p.createRun();
        r.setText(text);
        r.setBold(isHeader);
        r.setFontFamily("Helvetica");
        r.setFontSize(12);
        
        if (isHeader) {
            cell.setColor("F0F0F0");
        }
    }
    
    private static void addVulnSection(XWPFTable table, String title, String content) {
        if (content == null || content.trim().isEmpty()) {
            return;
        }
        
        XWPFTableRow row = table.createRow();
        XWPFTableCell cell = row.getCell(0);
        
        XWPFParagraph p = cell.getParagraphs().get(0);
        
        XWPFRun titleRun = p.createRun();
        titleRun.setText(title + ":");
        titleRun.setBold(true);
        titleRun.setFontFamily("Helvetica");
        titleRun.setFontSize(12);
        titleRun.addBreak();
        
        if (title.equals("Evidence Image")) {
            try {
                titleRun.addBreak();
                XWPFRun imageRun = p.createRun();
                
                // Resim formatını belirle
                String imagePath = content.toLowerCase();
                int pictureType;
                if (imagePath.endsWith(".png")) {
                    pictureType = XWPFDocument.PICTURE_TYPE_PNG;
                } else if (imagePath.endsWith(".jpg") || imagePath.endsWith(".jpeg")) {
                    pictureType = XWPFDocument.PICTURE_TYPE_JPEG;
                } else if (imagePath.endsWith(".gif")) {
                    pictureType = XWPFDocument.PICTURE_TYPE_GIF;
                } else {
                    throw new IllegalArgumentException("Unsupported image format");
                }
                
                // Resmi yükle ve boyutlandır
                FileInputStream imageStream = new FileInputStream(content);
                imageRun.addPicture(
                    imageStream,
                    pictureType,
                    content,
                    Units.toEMU(400), // width
                    Units.toEMU(300)  // height
                );
                imageStream.close();
                imageRun.addBreak();
            } catch (Exception e) {
                XWPFRun errorRun = p.createRun();
                errorRun.setText("Error loading image: " + e.getMessage());
                errorRun.setFontFamily("Helvetica");
                errorRun.setFontSize(12);
            }
        } else {
            XWPFRun contentRun = p.createRun();
            contentRun.setText(content);
            contentRun.setFontFamily("Helvetica");
            contentRun.setFontSize(12);
        }
    }
    
    private static String getRiskLevelColor(String risk) {
        switch (risk) {
            case "Critical": return "FF595E";
            case "High": return "FF914D";
            case "Medium": return "FFCA3A";
            case "Low": return "8AC926";
            default: return "1982C4";
        }
    }
} 