from classes.FlowClassifier import FlowClassifier

def main():
    model_path = "../../models/CIC_IDS_2017/xgb_clf_multiclass.pkl"
    classifier = FlowClassifier(model_path)
    classifier.start_capture()

if __name__ =="__main__":
    main()