<?php

namespace Database\Seeders;

use App\Http\Controllers\API\AntrianAPIController;
use App\Models\Dokter;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class DokterSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        $api = new AntrianAPIController();
        $poli = $api->ref_dokter()->response;
        foreach ($poli as $value) {
            Dokter::updateOrCreate(
                [
                    'kodedokter' => $value->kodedokter,
                ],
                [
                    'namadokter' => $value->namadokter,
                ]
            );
        }
    }
}
