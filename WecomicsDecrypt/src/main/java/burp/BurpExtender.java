package burp;

import burp.XXTEA;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.util.Arrays;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import javax.swing.BorderFactory;
import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.json.*;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPane;
    final JTextArea inputTextArea = new JTextArea(10, 20);
    final JTextArea outputTextArea = new JTextArea(10, 20);
    private String cryptKey = "fecc14025859abb1af75bdcd4b67f032";
    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("WecomicDecrypt");
        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);

        // create decrypt tool UI
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // main split pane
                mainPane = new JPanel(new BorderLayout());
                mainPane.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
                // create decrypt and encrypt text area
                inputTextArea.setLineWrap(true);
                outputTextArea.setLineWrap(true);
                outputTextArea.setEditable(false);
                JPanel decryptTextWrapper = new JPanel(new GridLayout(0, 2));
                JScrollPane inputScrollPanel = new JScrollPane(inputTextArea);
                JScrollPane outputScrollPanel = new JScrollPane(outputTextArea);

                // inputScrollPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
                // outputScrollPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
                // decryptTextWrapper.add(inputScrollPanel, BorderLayout.CENTER);
                // decryptTextWrapper.add(outputScrollPanel, BorderLayout.CENTER);

                // create decrypt button
                JButton decryptButton = new JButton("Decrypt!");
                JButton encryptButton = new JButton("Encrypt!");
                decryptButton.addActionListener(new DecryptButtonListener());
                encryptButton.addActionListener(new EncryptButtonListener());

                JPanel buttonPanel = new JPanel(new GridLayout(0, 2, 5, 5));
                buttonPanel.add(decryptButton);
                buttonPanel.add(new JLabel(""));
                buttonPanel.add(encryptButton);
                // decryptTextWrapper.add(buttonPanel, BorderLayout.CENTER);

                decryptTextWrapper.add(inputScrollPanel);
                decryptTextWrapper.add(buttonPanel);
                decryptTextWrapper.add(outputScrollPanel);

                mainPane.add(decryptTextWrapper, BorderLayout.PAGE_START);
                // mainPane.add(buttonPanel, BorderLayout.PAGE_END);
                callbacks.customizeUiComponent(mainPane);
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    // implement UI event listeners
    class DecryptButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent ae) {
            String inputText = new String(inputTextArea.getText());
            String decryptedData = XXTEA.decryptBase64StringToString(inputText, cryptKey);

            // if decrypted data is json, then try to beautify it
            if (isJSONValid(decryptedData)) {
                try {

                    String json = "";
                    Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create();
                    JsonParser jp = new JsonParser();
                    JsonElement je = jp.parse(decryptedData);
                    json = gson.toJson(je);
                    outputTextArea.setText(json);
                } catch (Exception e) {
                    outputTextArea.setText("Error" + e.toString());
                }
            } else {
                outputTextArea.setText(decryptedData);
            }
        }
    }

    class EncryptButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent ae) {
            String inputText = inputTextArea.getText();
            String encryptedData = XXTEA.encryptToBase64String(inputText, cryptKey);

            outputTextArea.setText(encryptedData);
        }
    }

    //
    // implement IMessageEditorTabFactory
    //

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // create a new instance of our custom editor tab
        return new DecryptTab(controller, editable);
    }

    @Override
    public String getTabCaption() {
        return "WecomicsDecrypt";
    }

    @Override
    public Component getUiComponent() {
        return mainPane;
    }

    public boolean isJSONValid(String test) {
        try {
            new JSONObject(test);
        } catch (JSONException ex) {
            // edited, to include @Arthur's comment
            // e.g. in case JSONArray is valid as well...
            try {
                new JSONArray(test);
            } catch (JSONException ex1) {
                return false;
            }
        }
        return true;
    }
    //
    // class implementing IMessageEditorTab
    //

    class DecryptTab implements IMessageEditorTab {
        private boolean editable;
        private ITextEditor txtInput;
        private byte[] currentMessage;

        private String patternURL = "bwapp";
        private boolean isTarget = false;
        private boolean modifiedJSON = false;

        public DecryptTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;

            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);
        }

        //
        // implement IMessageEditorTab
        //

        @Override
        public String getTabCaption() {
            return "WecomicDecrypt";
        }

        @Override
        public Component getUiComponent() {
            return txtInput.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            // it's type is not JSON, then decrypt it
            if (isRequest) {
                IRequestInfo requestInfo = helpers.analyzeRequest(content);
                if (requestInfo.getContentType() != IRequestInfo.CONTENT_TYPE_JSON) {
                    isTarget = true;
                    return true;
                }

            } else {
                // If the resonse it's type is not JSON, then try decrypt it
                IResponseInfo responseInfo = helpers.analyzeResponse(content);
                if (!responseInfo.getInferredMimeType().equals("json")) {
                    return true;
                }
            }

            return true;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content == null) {
                // clear our display
                txtInput.setText("no encrypted data".getBytes());
                txtInput.setEditable(false);
            } else {
                int bodyOffset;
                if (isRequest) {
                    IRequestInfo requestInfo = helpers.analyzeRequest(content);
                    bodyOffset = requestInfo.getBodyOffset();
                } else {
                    IResponseInfo responseInfo = helpers.analyzeResponse(content);
                    bodyOffset = responseInfo.getBodyOffset();
                }

                // Get the body part from requset or response
                byte[] requestResponseBody = Arrays.copyOfRange(content, bodyOffset, content.length);
                String decryptedData = XXTEA.decryptBase64StringToString(helpers.bytesToString(requestResponseBody),
                        cryptKey);

                if (isJSONValid(decryptedData)) {
                    String json = "";
                    Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create();
                    JsonParser jp = new JsonParser();
                    JsonElement je = jp.parse(decryptedData);
                    json = gson.toJson(je);
                    txtInput.setText(json.getBytes());
                } else {
                    txtInput.setText(decryptedData.getBytes());
                }
                txtInput.setEditable(editable);
                modifiedJSON = true;

            }

            // remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage() {
            // determine whether the user modified the deserialized data
            if (txtInput.isTextModified()) {
                String modifiedData = new String(txtInput.getText());
                if (isJSONValid(modifiedData)) {
                    // convert to normal json string without beautify
                    Gson gson = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
                    try {
                        JsonParser jp = new JsonParser();
                        JsonElement je = jp.parse(modifiedData);
                        modifiedData = gson.toJson(je);
                    } catch (Exception e) {
                        return currentMessage;
                    }
                }

                // encrypt data
                String encryptedData = XXTEA.encryptToBase64String(modifiedData, cryptKey);

                // update http request message
                IRequestInfo requestInfo = helpers.analyzeRequest(currentMessage);

                return helpers.buildHttpMessage(requestInfo.getHeaders(), encryptedData.getBytes());
            } else
                return currentMessage;
        }

        @Override
        public boolean isModified() {
            return txtInput.isTextModified();
        }

        @Override
        public byte[] getSelectedData() {
            return txtInput.getSelectedText();
        }
    }
}