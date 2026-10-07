"""Train optional experimental logistic risk scorer from analyst-labeled CSV."""
import argparse
from app.tools.risk_prediction import train_logistic_csv


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_path")
    parser.add_argument("--output", default="models/risk_model/model.json")
    args = parser.parse_args()
    model = train_logistic_csv(args.csv_path, args.output)
    print(f"Saved experimental model with {model['training_rows']} labeled rows. It is not validated for operational decisions.")


if __name__ == "__main__":
    main()
