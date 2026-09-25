import pandas as pd

DATASET_PATH = "ml/data/phishing_email.csv"


def main():
    print("Loading dataset...")
    df = pd.read_csv(DATASET_PATH)

    print("\n=== DATASET SHAPE ===")
    print(f"Rows: {len(df):,}")
    print(f"Columns: {len(df.columns)}")

    print("\n=== COLUMNS ===")
    print(df.columns.tolist())

    print("\n=== LABEL DISTRIBUTION ===")
    print(df["label"].value_counts())
    print("\nLabel percentages:")
    print(df["label"].value_counts(normalize=True).mul(100).round(2))

    print("\n=== MISSING VALUES ===")
    print(df.isnull().sum())

    print("\n=== DUPLICATES ===")
    print(f"Duplicate emails: {df['text_combined'].duplicated().sum():,}")

    print("\n=== EMAIL LENGTH ===")
    lengths = df["text_combined"].fillna("").str.len()

    print(f"Minimum: {lengths.min():,}")
    print(f"Maximum: {lengths.max():,}")
    print(f"Mean: {lengths.mean():,.2f}")
    print(f"Median: {lengths.median():,.2f}")

    print("\n=== EXAMPLES FOR EACH LABEL ===")

    for label in sorted(df["label"].unique()):
        print(f"\n--- LABEL {label} ---")
        samples = df[df["label"] == label]["text_combined"].head(3)

        for i, text in enumerate(samples, 1):
            print(f"\nExample {i}:")
            print(text[:500])


if __name__ == "__main__":
    main()