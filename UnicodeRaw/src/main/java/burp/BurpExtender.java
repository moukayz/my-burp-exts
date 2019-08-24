package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;
import java.net.URLDecoder;
import java.net.URLEncoder;

import org.omg.PortableInterceptor.RequestInfo;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private String extName = "UnicodeRaw";

    private PrintWriter stdOut;
    private PrintWriter stdErr;
    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        stdOut = new PrintWriter(callbacks.getStdout(), true);
        stdErr = new PrintWriter(callbacks.getStderr(), true);

        // set our extension name
        callbacks.setExtensionName(extName);

        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);
    }

    //
    // implement IMessageEditorTabFactory
    //

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // create a new instance of our custom editor tab
        return new UnicodeRawTab(controller, editable);
    }

    //
    // class implementing IMessageEditorTab
    //

    class UnicodeRawTab implements IMessageEditorTab {
        private boolean editable;
        private ITextEditor txtInput;
        private byte[] currentMessage;

        public UnicodeRawTab(IMessageEditorController controller, boolean editable) {
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
            return extName;
        }

        @Override
        public Component getUiComponent() {
            return txtInput.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            return true;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content == null) {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
            } else {
                byte[] decodedContent = content;
                txtInput.setEditable(editable);
                txtInput.setText(decodedContent);
            }

            // remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage() {
            if (txtInput.isTextModified()) {
                byte[] modifiedData = txtInput.getText();
                byte[] encodedData = modifiedData;

                IRequestInfo requestInfo = helpers.analyzeRequest(modifiedData);
                List<IParameter> params = requestInfo.getParameters();
                params.forEach(param -> {
                    if (param.getType() == IParameter.PARAM_BODY || param.getType() == IParameter.PARAM_URL) {
                        helpers.updateParameter(encodedData, helpers.buildParameter(param.getName(),
                                helpers.urlEncode(param.getValue()), param.getType()));
                    }
                });

                return encodedData;
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