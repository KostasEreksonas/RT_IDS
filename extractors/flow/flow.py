from classes.FlowClassifier import FlowClassifier

def main():
    model_path = "../../models/CIC_IDS_2017/xgb_clf_multiclass.pkl"
    anomaly_detector = "../../models/CIC_IDS_2017/isolation_forest.pkl"

    classifier = FlowClassifier(model_path, anomaly_detector)
    classifier.start_capture()

if __name__ =="__main__":
    main()