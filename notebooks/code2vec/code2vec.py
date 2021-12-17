from vocabularies import VocabType
from config import Config
from interactive_predict import InteractivePredictor
from model_base import Code2VecModelBase
import json

def load_model_dynamically(config: Config) -> Code2VecModelBase:
    assert config.DL_FRAMEWORK in {'tensorflow', 'keras'}
    if config.DL_FRAMEWORK == 'tensorflow':
        from tensorflow_model import Code2VecModel
    elif config.DL_FRAMEWORK == 'keras':
        from keras_model import Code2VecModel
    return Code2VecModel(config)

def load_issues():
    with open('../output/java_taints_c2v.json', encoding="utf-8") as json_file:
        return json.load(json_file)

def save_issues(issues):
    with open("../output/java_taints_predict.json", "w", encoding="utf-8") as json_file:
        json.dump(issues, json_file)

def to_input(issue):
    func = "void func() {\n"
    for taint in issue['cleared']:
        func += "\t" + taint["code"] + "\n"
    func += "}"
    with open('Input.java', 'w', encoding="utf-8") as java_file:
        java_file.write(func)

if __name__ == '__main__':
    config = Config(set_defaults=True, load_from_args=True, verify=True)

    model = load_model_dynamically(config)
    config.log('Done creating code2vec model')

    if config.is_training:
        model.train()
    if config.SAVE_W2V is not None:
        model.save_word2vec_format(config.SAVE_W2V, VocabType.Token)
        config.log('Origin word vectors saved in word2vec text format in: %s' % config.SAVE_W2V)
    if config.SAVE_T2V is not None:
        model.save_word2vec_format(config.SAVE_T2V, VocabType.Target)
        config.log('Target word vectors saved in word2vec text format in: %s' % config.SAVE_T2V)
    if (config.is_testing and not config.is_training) or config.RELEASE:
        eval_results = model.evaluate()
        if eval_results is not None:
            config.log(
                str(eval_results).replace('topk', 'top{}'.format(config.TOP_K_WORDS_CONSIDERED_DURING_PREDICTION)))
    if config.PREDICT:
        predictor = InteractivePredictor(config, model)
        feats = load_issues()
        for issue in feats:
            to_input(issue)
            prediction = predictor.predict()
            if prediction == None:
                continue
            (method_names, vector) = prediction
            issue["vector"] = vector.tolist()
            issue["set"] = list(set([item for pred in method_names for item in pred['name']]))
        save_issues(feats)
        
    model.close_session()
